import unittest
from app import app

class TestCVEFiltering(unittest.TestCase):
    
    def setUp(self):
        app.testing = True
        self.app = app.test_client()

    def test_specific_year_filter(self):
        response = self.app.get('/filter_cves?specific_year=1999')
        self.assertEqual(response.status_code, 200)  
       

    def test_cve_id_filter(self):
        response = self.app.get('/cves/CVE-2022-1234')
        self.assertEqual(response.status_code, 200) 
        

    def test_cve_sort(self):
        response = self.app.get('/cves/list?sort=base_score')
        self.assertEqual(response.status_code, 200)  
        

    def test_last_modified_filter(self):
        response = self.app.get('/cves/list?page=2')
        self.assertEqual(response.status_code, 200)
        

if __name__ == '__main__':
    unittest.main()
