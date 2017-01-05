import unittest
import pyghmi.ipmi.sdr as sdr

class TestSDR(unittest.TestCase):
    def setUp(self):
    	pass
    
    def test_ones_complement(self):
    	self.assertEqual(sdr.ones_complement(127,8), 127)
    	self.assertEqual(sdr.ones_complement(128,8), -127)
    	self.assertEqual(sdr.ones_complement(0,8), 0)
    	self.assertEqual(sdr.ones_complement(254,8), -1)

if __name__ == __main__:
    unittest.main()
