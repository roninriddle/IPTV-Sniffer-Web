"""Failure-boundary acceptance for the v1.3.5 optimization plan."""
import io
import json
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
import app as a
from test_regression_v134 import isolated, operator, archives
from services.backup_service import RestoreTransaction, validate_modules
from services.catchup_scheduler import CatchupScheduler
from services.diagnostic_service import playback_evidence, diagnostic_verdict, is_transport_stream
from services.media_task_service import MediaTaskManager, MediaCapacityError, reap_process
from services.snapshot_service import SnapshotService
from services.storage_service import OperatorChannelStore
from tools.check_release import check


def test_restore_write_failure_rolls_back_every_module_and_credentials(isolated, tmp_path, monkeypatch):
    import services.backup_service as backup
    a.settings_store.save({'http_port': 5140})
    a.epg_key_store.set_epg_key('synthetic-before')
    a.channel_store.save_rows([{'host':'239.1.1.1','port':5000,'name':'before'}])
    paths=[a.settings_store.path,a.epg_key_store.path,a.channel_store.path]
    before={p:p.read_bytes() for p in paths}
    real=backup.os.replace
    def fail_last(source, target):
        if Path(target)==a.settings_store.path and Path(source).name.startswith('new-'):
            raise OSError('synthetic disk failure')
        return real(source,target)
    monkeypatch.setattr(backup.os, 'replace', fail_last)
    with pytest.raises(OSError):
        a._restore_global_backup_payload({'settings':{'http_port':5150},
            'channels':{'changed':{'name':'after'}}, 'credentials':{'epg_des3_key':'synthetic-after'}},
            ['settings','channels','credentials'])
    assert all(p.read_bytes()==data for p,data in before.items())
    assert not list(tmp_path.glob('.restore-*'))


def test_archive_and_json_share_one_rollback(tmp_path, monkeypatch):
    import services.backup_service as backup
    existing=tmp_path/'settings.json'; existing.write_bytes(b'old')
    new=tmp_path/'archives'/'capture.pcap'
    tx=RestoreTransaction(tmp_path);tx.stage(new,b'pcap');tx.stage(existing,b'new')
    real=backup.os.replace
    def fail(source,target):
        if Path(target)==existing and Path(source).name.startswith('new-'): raise OSError('full')
        return real(source,target)
    monkeypatch.setattr(backup.os,'replace',fail)
    with pytest.raises(OSError): tx.commit()
    assert existing.read_bytes()==b'old' and not new.exists()


@pytest.mark.parametrize('payload', [
    {'schema_version':99}, {'channels':[]}, {'operator_channels':{'x':'bad'}},
    {'credentials':{'epg_des3_key':{}}}, {'subscription_candidates':{'candidate_ids':[{}]}},
])
def test_restore_schema_rejects_bad_modules_before_write(isolated, payload):
    result=isolated.post('/api/backup/import',json={'backup':payload,'modules':['channels','credentials']})
    assert result.status_code==400
    assert not a.channel_store.path.exists()


def test_media_capacity_keeps_management_responsive_and_can_cancel(isolated, monkeypatch):
    manager=MediaTaskManager(limit=1)
    monkeypatch.setattr(a,'media_tasks',manager)
    called=[];lease=manager.acquire('catchup','audit');lease.attach(lambda:called.append('closed'))
    response=isolated.get('/hls/239.1.1.1_5000/catchup?playseek=20261004010000-20261004020000')
    assert response.status_code==429 and response.headers['Retry-After']=='2'
    assert isolated.get('/api/settings').status_code==200
    assert isolated.delete('/api/media/tasks/'+lease.id).get_json()['data']['cancelled']
    assert called==['closed'] and manager.status()['active']==[]
    lease.close(); assert called==['closed']


def test_cancel_before_resource_attached_still_reaps_resource():
    manager=MediaTaskManager();lease=manager.acquire('catchup');lease.close()
    proc=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],stdout=subprocess.PIPE)
    lease.attach(lambda:reap_process(proc))
    assert proc.poll() is not None and proc.stdout.closed
    assert not manager.status()['active']


def test_shutdown_reaps_actual_child_and_rejects_new_work():
    manager=MediaTaskManager();lease=manager.acquire('snapshot')
    proc=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],stdout=subprocess.PIPE)
    lease.attach(lambda:reap_process(proc));manager.shutdown()
    assert proc.poll() is not None and proc.stdout.closed
    with pytest.raises(MediaCapacityError):manager.acquire('snapshot')


def test_response_closed_before_iteration_releases_catchup_resource(isolated, monkeypatch):
    manager=MediaTaskManager();monkeypatch.setattr(a,'media_tasks',manager)
    closed=[]
    def response(key,lease):
        lease.attach(lambda:closed.append(key))
        return a.Response(iter([b'ts']),mimetype='video/mp2t')
    monkeypatch.setattr(a,'_hls_catchup_response',response)
    result=isolated.get('/hls/239.1.1.1_5000/catchup',buffered=False)
    result.close()
    assert closed==['239.1.1.1_5000'] and not manager.status()['active']


def test_snapshot_cache_bound_interface_key_and_jpeg_validation(monkeypatch):
    import services.snapshot_service as snap
    commands=[]
    class Proc:
        returncode=0;stdout=None;stderr=None
        def poll(self):return 0
        def communicate(self,timeout):return b'\xff\xd8synthetic\xff\xd9',b''
    monkeypatch.setattr(snap.subprocess,'Popen',lambda cmd,**kw:commands.append(cmd) or Proc())
    service=SnapshotService(MediaTaskManager(),max_entries=2)
    service.get('239.1.1.1',5000,'rtp','192.0.2.1')
    service.get('239.1.1.1',5000,'rtp','192.0.2.1')
    assert len(commands)==1
    service.get('239.1.1.1',5000,'rtp','192.0.2.2')
    service.get('239.1.1.2',5000,'rtp','192.0.2.2')
    assert len(commands)==3 and len(service.cache)==2
    assert 'localaddr=192.0.2.1' in commands[0][commands[0].index('-i')+1]
    monkeypatch.setattr(Proc,'communicate',lambda *args,**kw:(b'not-jpeg',b''))
    with pytest.raises(ValueError):service.get('239.1.1.3',5000,'rtp','')
    assert not service.tasks.status()['active'] and not service.pending


def test_snapshot_duplicate_is_rejected_without_second_process(monkeypatch):
    import services.snapshot_service as snap
    started=threading.Event();release=threading.Event();commands=[]
    class Proc:
        returncode=0;stdout=None;stderr=None
        def poll(self):return 0
        def communicate(self,timeout):
            started.set();assert release.wait(2);return b'\xff\xd8x\xff\xd9',b''
    monkeypatch.setattr(snap.subprocess,'Popen',lambda *args,**kw:commands.append(args) or Proc())
    service=SnapshotService(MediaTaskManager())
    thread=threading.Thread(target=lambda:service.get('239.1.1.1',5000,'rtp',''));thread.start()
    assert started.wait(2)
    try:
        with pytest.raises(MediaCapacityError):service.get('239.1.1.1',5000,'rtp','')
    finally:release.set();thread.join(2)
    assert len(commands)==1 and not service.pending


def test_scheduler_restart_preserves_deadline_and_failed_precheck_backs_off(tmp_path,monkeypatch):
    import services.catchup_scheduler as schedule
    clock=[1000];monkeypatch.setattr(schedule.time,'time',lambda:clock[0])
    settings={'catchup_enabled':True,'catchup_auto_refresh_enabled':True,'catchup_auto_refresh_hours':1}
    first=CatchupScheduler(path=tmp_path/'schedule.json')
    assert first.next_run(settings,1000)==4600
    second=CatchupScheduler(path=first.path);second.load()
    assert second.next_run(settings,3000)==4600
    clock[0]=5000
    with pytest.raises(ValueError):second.run(settings,'auto',lambda:(_ for _ in ()).throw(ValueError('no lease')),str)
    assert second.next_run(settings,5060)==8600 and not second.state['running']
    third=CatchupScheduler(path=first.path);third.load()
    assert third.next_run(settings,6000)==8600


def test_layered_diagnosis_does_not_claim_media_from_wire_or_port():
    checks=playback_evidence({'wire_active_packets':8,'join_requested':True,'socket_active_packets':0},True)
    by_name={item['item']:item['ok'] for item in checks}
    assert by_name['实际观察到 IGMP'] is None
    assert by_name['应用 socket 收到数据'] is False
    assert by_name['FCC 起播与组播切换'] is None
    assert by_name['播放器首帧与持续播放'] is None
    assert '未验证' in diagnostic_verdict(checks)
    sections=a._diagnose_sections(checks)
    assert sum(len(s['checks']) for s in sections)==len(checks)


def test_transport_stream_evidence_checks_rtp_payload():
    ts=(b'\x47'+b'\0'*187)*2
    assert is_transport_stream(ts)
    assert is_transport_stream(b'\x80\x21'+b'\0'*10+ts)
    assert not is_transport_stream(b'random multicast datagram')


def test_parser_provenance_survives_operator_and_json_round_trip(isolated,tmp_path,monkeypatch):
    import services.stb_discovery_service as stb
    body=json.dumps({'channleInfoStruct':[{'channelName':'Fixture','channelURL':'rtp://239.1.2.3:5000','channelID':'42'}]}).encode()
    monkeypatch.setattr(stb,'_reassemble_tcp_streams',lambda path:{('192.0.2.1',80,'192.0.2.2',1000):body})
    channels=stb.analyze_pcap_for_channels('stb-boot-fixture.pcap','192.0.2.2')
    assert len(channels)==1
    provenance=channels[0]['provenance'];assert provenance['sources'][0]['parser']=='channel-acquire'
    assert provenance['sources'][0]['pcap']=='stb-boot-fixture.pcap'
    assert provenance['fields']['ip']==0
    a._do_operator_import(channels)
    saved=a.operator_channel_store.load()['239.1.2.3:5000']
    assert saved['provenance']==provenance
    row=a.channel_store.list()[0];assert row['provenance']==provenance
    path=tmp_path/'channels.json'
    a.export_service._write_playlist_json(a.export_service._normalize_channels([row]),path,'rtp')
    parsed,_=a.parse_exported_channels_json(json.loads(path.read_text()))
    assert parsed[0]['stable_id']==row['stable_id'] and parsed[0]['provenance']==provenance


def test_manual_source_and_history_are_separate_in_catalog(isolated):
    a._do_operator_import([operator('239.1.1.1')]);a._do_operator_import([operator('239.1.1.2')])
    a.channel_store.save_rows([{'host':'239.1.1.3','port':5000,'name':'manual'}])
    rows={v['row']['key']:v['row'] for v in a._stable_channel_catalog().values()}
    assert '239.1.1.1:5000' not in rows
    assert rows['239.1.1.3:5000']['source_origin']=='manual'
    api=isolated.get('/api/channels').get_json()['data']['channels']
    assert next(r for r in api if r['host']=='239.1.1.1')['source_state']=='historical'


def test_release_tag_cannot_mismatch_version(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    (tmp_path/'config.py').write_text('APP_VERSION="1.3.5-test"')
    for file in ('docker-compose.yml','docker-bake.hcl'):
        (tmp_path/file).write_text('roninriddle/iptv-sniffer-web:1.3.5-test')
    assert check(tmp_path,'v1.3.5-test')=='1.3.5-test'
    with pytest.raises(ValueError):check(tmp_path,'v1.3.4')


@pytest.mark.parametrize('name', ['ctc-setconfig.html','vsp.json','channel-acquire.json'])
def test_adapter_fixture_provenance_and_field_mapping(name,monkeypatch):
    import services.stb_discovery_service as stb
    body=(Path(__file__).parent/'fixtures'/'protocols'/name).read_bytes()
    response=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
    monkeypatch.setattr(stb,'_reassemble_tcp_streams',lambda path:{('192.0.2.10',80,'192.0.2.2',1000):response})
    rows=stb.analyze_pcap_for_channels('stb-boot-synthetic.pcap','192.0.2.2')
    assert len(rows)==1 and rows[0]['channel_id']=='101'
    row=rows[0];assert row['ip']=='239.1.2.3' and row['port']==5000
    evidence=row['provenance'];source=evidence['sources'][0]
    assert source['parser']==name.split('.')[0] and source['parser_version']=='1'
    assert source['pcap']=='stb-boot-synthetic.pcap' and len(source['body_sha256'])==64
    assert set(row)-{'provenance'}==set(evidence['fields'])


def test_hls_capacity_and_spawn_failure_leave_no_directory_or_lease(tmp_path,monkeypatch):
    import services.hls_service as hls
    tasks=MediaTaskManager(limit=1)
    service=hls.HlsService(SimpleNamespace(info=lambda *_:None),tasks)
    monkeypatch.setattr(hls,'HLS_BASE_DIR',tmp_path)
    lease=tasks.acquire('snapshot')
    with pytest.raises(MediaCapacityError):service.ensure('239.1.2.3',5000)
    assert not list(tmp_path.iterdir())
    lease.close()
    monkeypatch.setattr(hls.subprocess,'Popen',lambda *a,**k:(_ for _ in ()).throw(OSError('synthetic spawn failure')))
    with pytest.raises(OSError):service.ensure('239.1.2.3',5000)
    assert not list(tmp_path.iterdir()) and not tasks.status()['active']
    service.shutdown()


def test_cooperative_cancel_keeps_capacity_until_worker_finishes():
    tasks=MediaTaskManager(limit=1);lease=tasks.acquire('diagnose');event=threading.Event()
    lease.cancel_callback=event.set
    assert tasks.cancel(lease.id) and event.is_set()
    with pytest.raises(MediaCapacityError):tasks.acquire('snapshot')
    lease.close();assert not tasks.status()['active']


def test_rtsp_cancel_during_connect_closes_late_socket(monkeypatch):
    import socket
    from services.rtsp_catchup_service import CombinedRtspUdpSession, RtspCatchupError
    session=CombinedRtspUdpSession('rtsp://192.0.2.10/media')
    first,second=socket.socketpair()
    def connect(url):
        session.close()
        return first
    monkeypatch.setattr(session,'_connect',connect)
    try:
        with pytest.raises(RtspCatchupError,match='rtsp_cancelled'):session.open()
        assert first.fileno()==-1
    finally: first.close();second.close()


def test_stale_offline_capture_result_cannot_restore_token_or_state(tmp_path,monkeypatch):
    import services.stb_discovery_service as stb
    logger=SimpleNamespace(info=lambda *_:None,warning=lambda *_:None,error=lambda *_:None)
    service=stb.StbDiscoveryService(logger,archive_dir=tmp_path)
    archive=tmp_path/'stb-boot-fixture.pcap';archive.write_bytes(b'fixture')
    monkeypatch.setattr(stb,'_reassemble_tcp_streams',lambda _: {})
    monkeypatch.setattr(service,'_persist_protocol_artifacts',lambda *args: {})
    def analyze(*args):
        service.reset()
        return [{'name':'stale'}]
    monkeypatch.setattr(stb,'analyze_pcap_for_channels',analyze)
    monkeypatch.setattr(stb,'_detect_timeshift_host',lambda *args:'')
    monkeypatch.setattr(stb,'_extract_dhcp_from_pcap',lambda *args:{})
    monkeypatch.setattr(stb,'_extract_epg_credentials',lambda *args:{})
    monkeypatch.setattr(stb,'_extract_ctc_portal_auth',lambda *args:{'user_token':'synthetic'})
    service.token_store=SimpleNamespace(save_token=lambda _:pytest.fail('stale token persisted'))
    result=service.reanalyze_latest_archive('192.0.2.2')
    assert result['status']==service.STATUS_IDLE and result['channels']==[]


def test_disaster_export_preflights_before_compressing(isolated,tmp_path,monkeypatch):
    import zipfile
    monkeypatch.setattr(a,'_DISASTER_MAX_UNCOMPRESSED_BYTES',10)
    monkeypatch.setattr(zipfile,'ZipFile',lambda *args,**kwargs:pytest.fail('compression began before preflight'))
    response=isolated.post('/api/backup/disaster-export',json={'confirmed':True,'modules':['settings']})
    assert response.status_code==400
    assert not list(a.DATA_DIR.glob('.iptv-disaster-*'))


@pytest.mark.parametrize('window,valid',[
    ('20261003235500-20261004001000',True),
    ('20260230000000-20260301010000',False),
    ('20261004010000-20261004000000',False),
    ('20261004000000-20261004000000',False),
])
def test_utc_playseek_calendar_and_midnight(window,valid):
    from utils import valid_playseek,with_playseek
    assert valid_playseek(window) is valid
    url=with_playseek('rtsp://192.0.2.1/a?token=a%2Fb&playseek=old&fcc=192.0.2.2:8027&fec=9000',window)
    assert url.count('playseek=')==1 and 'token=a%2Fb&fcc=192.0.2.2:8027&fec=9000' in url
    assert url.endswith(window)


def test_media_interface_is_independent_of_capture(monkeypatch):
    calls=[]
    def run(command,**kwargs):
        calls.append(command);return SimpleNamespace(stdout='[{"addr_info":[{"local":"192.0.2.42"}]}]')
    monkeypatch.setattr(a.subprocess,'run',run)
    assert a._iptv_local_ip({'interface':'capture0','media_interface':'media0'})=='192.0.2.42'
    assert calls[0][-1]=='media0'


def test_stderr_pressure_is_drained_and_bounded():
    from services.media_task_service import ProcessTail
    proc=subprocess.Popen([sys.executable,'-c','import sys;sys.stderr.buffer.write(b"x"*2000000+b"TAIL");sys.stderr.flush()'],stderr=subprocess.PIPE)
    tail=ProcessTail(proc.stderr,limit=1024)
    try:
        assert proc.wait(timeout=5)==0
        text=tail.text();assert len(text)<=1024 and text.endswith('TAIL')
    finally: reap_process(proc)


def test_rtsp_keepalive_fallback_and_sequence_wrap(monkeypatch):
    from services.rtsp_catchup_service import CombinedRtspUdpSession
    session=CombinedRtspUdpSession('rtsp://192.0.2.1/test')
    session._keepalive_at=0;session.session_id='synthetic';methods=[]
    monkeypatch.setattr(session,'_send',lambda method,*args:methods.append(method))
    replies=iter([(405,{},b''),(200,{},b'')]);monkeypatch.setattr(session,'_read_response',lambda:next(replies))
    session._keepalive();assert methods==['GET_PARAMETER','OPTIONS']
    session._keepalive();assert len(methods)==2
    for seq in (65535,0,2,1,2):
        session._record_rtp_sequence(b'\x80\x21'+seq.to_bytes(2,'big')+b'\0'*8)
    assert session.rtp_stats=={'packets':5,'sequence_gaps':1,'late_or_duplicate':2}


@pytest.mark.parametrize('magic,endian',[(b'\xd4\xc3\xb2\xa1','<'),(b'\xa1\xb2\xc3\xd4','>'),(b'\x4d\x3c\xb2\xa1','<'),(b'\xa1\xb2\x3c\x4d','>')])
def test_pcap_byte_orders_and_precisions_are_bounded(tmp_path,magic,endian):
    import struct
    from services.io_limits import iter_pcap_packets
    path=tmp_path/'test.pcap';header=magic+struct.pack(endian+'HHIIII',2,4,0,0,65535,1)
    path.write_bytes(header+struct.pack(endian+'IIII',0,0,3,3)+b'abc')
    assert list(iter_pcap_packets(path))==[(1,b'abc')]
    path.write_bytes(header+struct.pack(endian+'IIII',0,0,0xffffffff,0xffffffff))
    with pytest.raises(ValueError,match='长度'):list(iter_pcap_packets(path))


def test_gzip_expansion_and_disallowed_redirect_are_rejected():
    import gzip
    from urllib.request import Request
    from services.io_limits import gunzip_bounded,validate_http_url,HttpOnlyRedirects
    with pytest.raises(ValueError):gunzip_bounded(gzip.compress(b'x'*10000),100)
    for url in ('file:///tmp/synthetic','ftp://192.0.2.1/test','http://user:pass@192.0.2.1/test'):
        with pytest.raises(ValueError):validate_http_url(url)
    assert validate_http_url('http://192.168.3.6:5140/iptv')
    with pytest.raises(ValueError):HttpOnlyRedirects().redirect_request(Request('http://192.0.2.1'),None,302,'',{},'file:///tmp/synthetic')


def test_operator_import_failure_is_atomic_across_stores(isolated,monkeypatch):
    import services.backup_service as backup
    a._do_operator_import([operator('239.1.1.1')])
    stores=(a.operator_channel_store,a.fcc_store,a.channel_store)
    before={store.path:store.path.read_bytes() for store in stores}
    replace=backup.os.replace
    def fail(source,target):
        if Path(target)==a.channel_store.path and Path(source).name.startswith('new-'):raise OSError('synthetic full disk')
        return replace(source,target)
    monkeypatch.setattr(backup.os,'replace',fail)
    with pytest.raises(OSError):a._do_operator_import([operator('239.1.1.2')])
    assert all(path.read_bytes()==content for path,content in before.items())


def test_refresh_cannot_overwrite_imported_operator_state(tmp_path):
    import copy
    store=OperatorChannelStore(tmp_path/'operator.json')
    store.save_dict({'a':{'name':'before'}});expected=store.load();changed=copy.deepcopy(expected)
    changed['a']['name']='refreshed'
    assert store.load()==expected  # caller changes cannot mutate cached state
    store.save_dict({'b':{'name':'imported'}})
    with pytest.raises(RuntimeError):store.save_if_unchanged(expected,changed)
    assert store.load()=={'b':{'name':'imported'}}


def test_export_bundles_do_not_cross_user_downloads(isolated,monkeypatch):
    from services.export_service import ExportService
    monkeypatch.setattr(a,'export_service',ExportService(a.OUTPUT_DIR))
    first=a.export_service.export_bundle([{'host':'239.1.1.1','port':5000,'name':'first'}],{})
    second=a.export_service.export_bundle([{'host':'239.1.1.2','port':5000,'name':'second'}],{})
    assert first['bundle']!=second['bundle']
    for result,wanted,unwanted in ((first,'first','second'),(second,'second','first')):
        response=isolated.get(f"/api/download/bundles/{result['bundle']}/channels.json")
        assert response.status_code==200
        assert wanted in response.get_data(as_text=True) and unwanted not in response.get_data(as_text=True)
    assert isolated.get('/api/download/bundles/invalid/channels.json').status_code==404


def test_epg_primary_switch_periodic_due_and_failure_backoff(tmp_path,monkeypatch):
    import services.epg_service as epg
    from services.log_service import AppLogger
    service=epg.EpgService(AppLogger(tmp_path/'app.log'),tmp_path/'epg.json')
    def fetch(url):return f'<tv><channel id="{url[-1]}"><display-name>Fixture</display-name></channel></tv>'.encode()
    monkeypatch.setattr(service,'_fetch',fetch)
    service.refresh('http://192.0.2.1/a');service.refresh('http://192.0.2.1/b')
    assert service.match('Fixture')['id']=='a'
    service.select_primary('http://192.0.2.1/b')
    assert service.match('Fixture')['id']=='b'
    reloaded=epg.EpgService(service.logger,service.cache_path)
    assert reloaded.match('Fixture')['id']=='b'
    calls=[];monkeypatch.setattr(service,'refresh_async',lambda *args:calls.append(args))
    now=int(epg.time.time());monkeypatch.setattr(epg.time,'time',lambda:now)
    settings={'epg_url':'http://192.0.2.1/b','use_logo':False,'auto_epg':True}
    service.auto_refresh_tick(settings);assert not calls
    monkeypatch.setattr(epg.time,'time',lambda:now+epg.EPG_REFRESH_INTERVAL+1)
    service.auto_refresh_tick(settings);assert len(calls)==1
    service._last_attempt[settings['epg_url']]=now+epg.EPG_REFRESH_INTERVAL+1
    service.auto_refresh_tick(settings);assert len(calls)==1


def test_log_redaction_and_rotation_apply_to_memory_and_disk(tmp_path):
    from services.log_service import AppLogger
    logger=AppLogger(tmp_path/'app.log',max_bytes=100,backups=2)
    for _ in range(20):logger.info('password=synthetic-secret token=synthetic-token rtsp://192.0.2.1/a?secret=x')
    entries=logger.read()['entries'];files=list(tmp_path.iterdir())
    assert len(files)==3 and 'synthetic-secret' not in str(entries) and 'synthetic-token' not in str(entries)
    assert all('synthetic-secret' not in p.read_text() and p.stat().st_mode & 0o077==0 for p in files)


@pytest.mark.parametrize('url', ['file:///tmp/synthetic', 'ftp://192.0.2.1/a', 'data:text/plain,synthetic'])
def test_remote_playlist_and_catchup_reject_local_protocols(isolated, url, monkeypatch):
    monkeypatch.setattr(a, 'media_tasks', MediaTaskManager())
    with pytest.raises(ValueError):a.fetch_text_resource(url)
    a.operator_channel_store.save_dict({'239.1.2.3:5000':{'backtv_url':url}})
    monkeypatch.setattr(a.subprocess,'Popen',lambda *args,**kwargs:pytest.fail('unsafe process launched'))
    response=isolated.get('/hls/239.1.2.3_5000/catchup?playseek=20261003235500-20261004001000')
    assert response.status_code==400


def test_hls_duplicate_start_waiter_is_rejected(tmp_path):
    from services.hls_service import HlsService
    service=HlsService(SimpleNamespace(info=lambda *_:None))
    try:
        service.claim_waiter('239.1.2.3_5000')
        with pytest.raises(MediaCapacityError):service.claim_waiter('239.1.2.3_5000')
        service.release_waiter('239.1.2.3_5000')
        service.claim_waiter('239.1.2.3_5000')
    finally:service.shutdown()


def test_legacy_fallback_source_label_matches_active_catalog(isolated):
    a.channel_store.save_rows([{'host':'239.1.2.3','port':5000,'name':'legacy','stable_id':'c-101'}])
    rows=isolated.get('/api/channels').get_json()['data']['channels']
    assert rows[0]['source_state']=='current'
    assert isolated.get('/live/c-101').status_code==307
