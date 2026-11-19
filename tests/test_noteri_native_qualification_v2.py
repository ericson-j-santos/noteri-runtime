"""Regression checks for Windows rollback manifest v2 (no live SQL)."""
from pathlib import Path
import hashlib,json,stat,tempfile,unittest,unittest.mock as mock
import importlib.util
BASE=Path(__file__).resolve().parents[1]
SOURCE=BASE/'scripts'/'noteri_native_qualification.py'

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

q=load(SOURCE,'fixed')
class FakeWin:
    @staticmethod
    def _validate_windows_persisted_state(value, name):
        if value!={'test': 'win-metadata'}:raise ValueError('invalid windows metadata')
    @staticmethod
    def _windows_persisted_file_state(path):
        if '.alt' in str(path) or 'badacl' in str(path):return {'test':'wrong'}
        return {'test':'win-metadata'}
    @staticmethod
    def _windows_persisted_state_equivalent(expected, actual):
        return expected==actual

class Tests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)/'install';self.root.mkdir()
        self.backup=self.root/'backup-fixture';self.backup.mkdir()
        self.entries={}
        self.files={}
        for i,rel in enumerate(sorted(q.MANAGED)):
            f=self.root/rel;f.parent.mkdir(parents=True,exist_ok=True)
            saved=self.backup/'files'/rel;saved.parent.mkdir(parents=True,exist_ok=True)
            a=f'old-{i}'.encode();b=f'new-{i}'.encode();f.write_bytes(a);saved.write_bytes(a)
            self.files[rel]={'sha256':hashlib.sha256(b).hexdigest(),'size':len(b)}
            self.entries[rel]={
                'existed':True,'source':'scripts/'+Path(rel).name if rel.endswith('.py') else 'config/command-gateway.policy.json',
                'previous_sha256':hashlib.sha256(a).hexdigest(), 'previous_size':len(a),
                'previous_mode':stat.S_IMODE(f.stat().st_mode),
                'desired_sha256':hashlib.sha256(b).hexdigest(),'desired_size':len(b),
                'previous_windows_state':{'test':'win-metadata'},
            }
        self.manifest={'version':2,'metadata_contract':'windows-owner-group-dacl-ads-v1','install_root':str(self.root),'entries':self.entries}
        self.receipt={'backup_dir':str(self.backup),'result':'HOST_UPDATE_BLOCKED','files':self.files}
        self.save()
    def save(self):
        (self.root/'update-receipt.json').write_text(json.dumps(self.receipt))
        (self.backup/'rollback-manifest.json').write_text(json.dumps(self.manifest))
    def call(self):
        with mock.patch.object(q,'_is_windows',return_value=True), mock.patch.object(q,'_windows_metadata_helper',return_value=FakeWin()):
            return q.rollback_readback(self.root)
    def test_02_valid_v2_previous_backup_and_windows_metadata(self):
        o=self.call();self.assertTrue(o['state_verified']);self.assertTrue(o['matches_previous'])
    def test_03_successful_installed_desired_bundle(self):
        for i,rel in enumerate(sorted(q.MANAGED)):
            (self.root/rel).write_bytes(f'new-{i}'.encode())
        self.receipt['result']='HOST_UPDATE_OK';self.save()
        o=self.call();self.assertTrue(o['state_verified']);self.assertFalse(o['matches_previous'])
    def test_04_unknown_schema_rejected(self):
        self.manifest['version']=3;self.save()
        with self.assertRaisesRegex(q.Blocked,'rollback_manifest_invalid'):self.call()
    def test_05_v1_windows_rejected(self):
        self.manifest['version']=1;self.save()
        with self.assertRaisesRegex(q.Blocked,'windows_rollback_v1_unverifiable'):self.call()
    def test_06_wrong_windows_contract_rejected(self):
        self.manifest['metadata_contract']='posix-mode-v1';self.save()
        with self.assertRaisesRegex(q.Blocked,'rollback_metadata_contract_invalid'):self.call()
    def test_07_windows_metadata_missing_rejected(self):
        del self.entries[sorted(q.MANAGED)[0]]['previous_windows_state'];self.save()
        with self.assertRaisesRegex(q.Blocked,'rollback_windows_metadata_missing'):self.call()
    def test_08_bad_windows_schema_rejected(self):
        self.entries[sorted(q.MANAGED)[0]]['previous_windows_state']={'fake':'badacl'};self.save()
        with self.assertRaisesRegex(q.Blocked,'windows_metadata_unverified'):self.call()
    def test_09_hash_changed_backup_blocks_success(self):
        self.receipt['result']='HOST_UPDATE_OK';self.save()
        (self.backup/'files'/sorted(q.MANAGED)[0]).write_bytes(b'tampered')
        self.assertFalse(self.call()['state_verified'])
    def test_10_hash_changed_installed_blocks_success(self):
        self.receipt['result']='HOST_UPDATE_OK';self.save()
        (self.root/sorted(q.MANAGED)[0]).write_bytes(b'tampered')
        self.assertFalse(self.call()['state_verified'])
    def test_11_missing_entry_rejected(self):
        del self.entries[sorted(q.MANAGED)[0]];self.save()
        with self.assertRaisesRegex(q.Blocked,'rollback_manifest_invalid'):self.call()
    def test_12_missing_backup_blocks(self):
        (self.backup/'files'/sorted(q.MANAGED)[0]).unlink()
        with self.assertRaises((FileNotFoundError,q.Blocked)):self.call()
    def test_13_symlink_backup_rejected(self):
        f=self.backup/'files'/sorted(q.MANAGED)[0];f.unlink();f.symlink_to(self.root/sorted(q.MANAGED)[0])
        with self.assertRaises(q.Blocked):self.call()
    def test_14_wrong_install_location_rejected(self):
        self.manifest['install_root']=str(self.root.parent);self.save()
        with self.assertRaisesRegex(q.Blocked,'rollback_manifest_invalid'):self.call()
    def test_15_invalid_desired_sha_rejected(self):
        self.entries[sorted(q.MANAGED)[0]]['desired_sha256']='invalid';self.save()
        with self.assertRaisesRegex(q.Blocked,'rollback_entry_invalid'):self.call()
    def test_16_missing_metadata_helper_rejected(self):
        with mock.patch.object(q,'_is_windows',return_value=True):
            with self.assertRaises(q.Blocked):q.rollback_readback(self.root)
    def test_17_replay_read_only(self):
        before={str(p):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(self.call(),self.call())
        self.assertEqual(before,{str(p):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
    def test_18_failed_update_cannot_pass_when_current_changed(self):
        (self.root/sorted(q.MANAGED)[0]).write_bytes(b'wrong')
        self.assertFalse(self.call()['state_verified'])
    def test_19_invalid_receipt_status_stays_blocked(self):
        self.receipt['result']='unknown';self.save()
        self.assertFalse(self.call()['state_verified'])
    def test_20_damaged_manifest_blocks(self):
        (self.backup/'rollback-manifest.json').write_text('{garbage')
        with self.assertRaisesRegex(q.Blocked,'rollback_manifest_invalid'):self.call()
    def test_21_unexpected_new_file_metadata_rejected(self):
        k=sorted(q.MANAGED)[0];self.entries[k]={'existed':False,'previous_windows_state':{'test':'win-metadata'},'desired_sha256':'0'*64,'desired_size':0,'source':'scripts/command_gateway.py'};self.save()
        with self.assertRaisesRegex(q.Blocked,'rollback_entry_invalid'):self.call()
    def test_22_success_without_metadata_proof_rejected(self):
        self.receipt['result']='HOST_UPDATE_OK';self.save()
        with mock.patch.object(q,'_is_windows',return_value=True),mock.patch.object(q,'_windows_metadata_helper',return_value=FakeWin()):
            with mock.patch.object(q,'_windows_metadata_equal',return_value=False):
                self.assertFalse(q.rollback_readback(self.root)['state_verified'])
    def test_23_source_file_mapping_cannot_change(self):
        k='bin/command_gateway.py'
        self.entries[k]['source']='scripts/session_launcher.py';self.save()
        with self.assertRaisesRegex(q.Blocked,'rollback_entry_invalid'):self.call()
    def test_24_unexpected_backup_when_previously_absent(self):
        k='bin/command_gateway.py'
        self.entries[k]={'existed':False,'source':'scripts/command_gateway.py','desired_sha256':'0'*64,'desired_size':0}
        self.save()
        with self.assertRaisesRegex(q.Blocked,'unexpected_backup_for_new_file'):self.call()
    def test_25_unexpected_symlink_when_previously_absent(self):
        k='bin/command_gateway.py'
        self.entries[k]={'existed':False,'source':'scripts/command_gateway.py','desired_sha256':'0'*64,'desired_size':0}
        (self.backup/'files'/k).unlink()
        (self.root/k).unlink()
        (self.root/k).symlink_to(self.root/'missing')
        self.save()
        self.assertFalse(self.call()['matches_previous'])
    def test_26_boolean_desired_size_rejected(self):
        k='bin/command_gateway.py';self.entries[k]['desired_size']=True;self.save()
        with self.assertRaisesRegex(q.Blocked,'rollback_entry_invalid'):self.call()
    def test_27_missing_receipt_not_claimed_as_qualified(self):
        (self.root/'update-receipt.json').unlink()
        r=self.call();self.assertIsNone(r['state_verified']);self.assertEqual(r['status'],'no_update_receipt')
    def test_28_win_metadata_changes_between_reads_rejected(self):
        count={}
        def changing(path):
            key=str(path);count[key]=count.get(key,0)+1
            return {'test':'win-metadata','seq':count[key]}
        fake=FakeWin();fake._windows_persisted_file_state=changing
        with mock.patch.object(q,'_is_windows',return_value=True),mock.patch.object(q,'_windows_metadata_helper',return_value=fake):
            self.assertFalse(q.rollback_readback(self.root)['state_verified'])
    def test_29_unknown_receipt_fail_closed_despite_valid_current(self):
        for i,rel in enumerate(sorted(q.MANAGED)):
            (self.root/rel).write_bytes(f'new-{i}'.encode())
        self.receipt['result']='UNKNOWN';self.save()
        self.assertFalse(self.call()['state_verified'])
if __name__=='__main__':unittest.main(verbosity=2)
