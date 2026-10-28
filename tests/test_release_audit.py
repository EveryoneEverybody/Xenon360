"""Adversarial public-package checks using generated, redistributable fixtures."""
import io,tempfile,unittest,zipfile
from pathlib import Path
from release_audit import inspect

class ArchiveAuditTest(unittest.TestCase):
    def scan(self,data,name='fixture.zip',deny=None):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/name;p.write_bytes(data)
            return inspect([(name,p)],deny)
    def zip(self,name,data,comment=b''):
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as z:
            z.writestr(name,data);z.comment=comment
        return out.getvalue()
    def test_nested_utf16_and_comment(self):
        marker='private'+'fixturemarker'
        inner=self.zip('Example.class',marker.encode('utf-16-le'))
        result=self.scan(self.zip('lib/example.jar',inner,marker.encode()),deny={'fixture':marker})
        self.assertEqual(result['result'],'FAIL')
        self.assertTrue(any(f['path'].endswith('!<comment>') for f in result['findings']))
        self.assertTrue(any(f['path'].endswith('!Example.class') for f in result['findings']))
    def test_unsafe_path(self):
        with self.assertRaises(ValueError):self.scan(self.zip('../escape.txt',b'x'))
    def test_git_history(self):
        self.assertEqual(self.scan(self.zip('.git/config',b'fixture'))['result'],'FAIL')
    def test_proprietary_extension(self):
        self.assertEqual(self.scan(self.zip('retail.'+'xex',b'not an executable'))['result'],'FAIL')
    def test_private_address(self):
        value='.'.join(['192','168','42','17']).encode()
        self.assertEqual(self.scan(value,'fixture.txt')['result'],'FAIL')
    def test_valid_nested_archive(self):
        self.assertEqual(self.scan(self.zip('lib/example.jar',self.zip('Example.class',b'fixture')))['result'],'PASS')

if __name__=='__main__':unittest.main()
