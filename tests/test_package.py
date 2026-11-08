import base64,hashlib,json,unittest
from pathlib import Path
from html.parser import HTMLParser
ROOT=Path(__file__).resolve().parents[1]
class PackageTests(unittest.TestCase):
 def test_manifest_has_least_permissions_and_stable_identity(self):
  manifest=json.loads((ROOT/'extensao/manifest.json').read_text())
  self.assertEqual(manifest['manifest_version'],3)
  self.assertEqual(set(manifest['permissions']),{'activeTab','storage'})
  self.assertEqual(manifest['host_permissions'],['http://127.0.0.1/*'])
  self.assertNotIn('content_scripts',manifest);self.assertNotIn('externally_connectable',manifest)
  digest=hashlib.sha256(base64.b64decode(manifest['key'])).hexdigest()[:32]
  expected=''.join(chr(ord('a')+int(x,16)) for x in digest)
  self.assertEqual(json.loads((ROOT/'backend/extension-identity.json').read_text())['id'],expected)
 def test_all_manifest_resources_and_external_popup_scripts_exist(self):
  manifest=json.loads((ROOT/'extensao/manifest.json').read_text())
  names=[manifest['background']['service_worker'],manifest['action']['default_popup'],*manifest['icons'].values()]
  for name in names:self.assertTrue((ROOT/'extensao'/name).is_file(),name)
  class Parser(HTMLParser):
   def handle_starttag(self,tag,attrs):
    data=dict(attrs)
    if tag=='script':
     self_outer.assertIn('src',data);self_outer.assertTrue((ROOT/'extensao'/data['src']).is_file())
    for key in data:self_outer.assertFalse(key.startswith('on'))
  self_outer=self;Parser().feed((ROOT/'extensao/popup.html').read_text())
 def test_shipped_code_has_no_remote_scripts_or_dynamic_html(self):
  for name in ('common.js','popup.js','worker.js'):
   code=(ROOT/'extensao'/name).read_text()
   self.assertNotIn('innerHTML',code);self.assertNotIn('eval(',code)
  self.assertNotIn('unsafe-eval',json.loads((ROOT/'extensao/manifest.json').read_text())['content_security_policy']['extension_pages'])
if __name__=='__main__':unittest.main()
