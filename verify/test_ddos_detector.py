# test_ddos_detector.py
import unittest
import time
from unittest.mock import patch

# Import the function and helpers from your module
from ddos_detector import is_potential_ddos, reset_tracker, TIME_WINDOW, MAX_REQUESTS, ip_tracker

class TestDdosDetector(unittest.TestCase):

    def setUp(self):
        """
        Called before each test method. Ensures a clean state.
        """
        reset_tracker() # Reset the global tracker

    def test_first_request_is_not_ddos(self):
        """Test that a single request is never flagged."""
        ip = "192.168.1.1"
        path = "/home"
        self.assertFalse(is_potential_ddos(ip, path), "First request should not be DDoS")
        # Check internal state (optional but good)
        self.assertEqual(ip_tracker[ip]['count'], 1, "Count should be 1 after first request")

    def test_requests_within_limit(self):
        """Test requests staying under the limit within the window."""
        ip = "192.168.1.2"
        path = "/page"
        start_time = 1000.0

        # Use patch to control time.time()
        with patch('ddos_detector.time.time', return_value=start_time):
            for i in range(MAX_REQUESTS):
                is_ddos = is_potential_ddos(ip, f"{path}{i}")
                self.assertFalse(is_ddos, f"Request {i+1} should not be DDoS")

        # Check internal state
        self.assertEqual(ip_tracker[ip]['count'], MAX_REQUESTS, f"Count should be {MAX_REQUESTS}")
        self.assertEqual(ip_tracker[ip]['window_start'], start_time, "Window start time should be set")

    def test_requests_exceeding_limit(self):
        """Test that requests are flagged after exceeding the limit."""
        ip = "192.168.1.3"
        path = "/api/data"
        start_time = 2000.0

        with patch('ddos_detector.time.time', return_value=start_time):
            # Send requests up to the limit - should all be False
            for i in range(MAX_REQUESTS):
                self.assertFalse(is_potential_ddos(ip, f"{path}{i}"), f"Request {i+1} should not be DDoS")

            # The very next request should trigger the flag
            self.assertTrue(is_potential_ddos(ip, f"{path}{MAX_REQUESTS}"), f"Request {MAX_REQUESTS+1} SHOULD be DDoS")

            # Subsequent requests should also be flagged within the same window
            self.assertTrue(is_potential_ddos(ip, f"{path}{MAX_REQUESTS+1}"), f"Request {MAX_REQUESTS+2} should also be DDoS")

        # Check internal state
        self.assertEqual(ip_tracker[ip]['count'], MAX_REQUESTS + 2, "Count should reflect all requests")
        self.assertEqual(ip_tracker[ip]['window_start'], start_time, "Window start time should remain the same")

    def test_window_reset(self):
        """Test that the count resets after the time window expires."""
        ip = "192.168.1.4"
        path = "/login"
        time1 = 3000.0
        time2 = time1 + TIME_WINDOW + 1 # Time just after the window expires

        # Mock time.time() sequentially
        mock_time = patch('ddos_detector.time.time')
        mock_time_instance = mock_time.start() # Start patching
        self.addCleanup(mock_time.stop) # Ensure patch stops even if test fails

        # Send one request at time1
        mock_time_instance.return_value = time1
        self.assertFalse(is_potential_ddos(ip, path), "First request at time1")
        self.assertEqual(ip_tracker[ip]['count'], 1)
        self.assertEqual(ip_tracker[ip]['window_start'], time1)

        # Send another request at time2 (after window expiry)
        mock_time_instance.return_value = time2
        self.assertFalse(is_potential_ddos(ip, path), "Request after window reset should not be DDoS")

        # Check internal state - should be reset
        self.assertEqual(ip_tracker[ip]['count'], 1, "Count should reset to 1")
        self.assertEqual(ip_tracker[ip]['window_start'], time2, "Window start time should update to time2")

    def test_multiple_ips_independent(self):
        """Test that tracking for different IPs is independent."""
        ip1 = "10.0.0.1"
        ip2 = "10.0.0.2"
        path = "/resource"
        start_time = 4000.0

        with patch('ddos_detector.time.time', return_value=start_time):
            # Send MAX_REQUESTS from ip1
            for i in range(MAX_REQUESTS):
                self.assertFalse(is_potential_ddos(ip1, f"{path}{i}"), f"IP1 Req {i+1} OK")

            # Send 1 request from ip2 - should be fine
            self.assertFalse(is_potential_ddos(ip2, path), "IP2 first request OK")
            self.assertEqual(ip_tracker[ip2]['count'], 1)
            self.assertEqual(ip_tracker[ip2]['window_start'], start_time)

            # Send one more request from ip1 - should be flagged
            self.assertTrue(is_potential_ddos(ip1, f"{path}{MAX_REQUESTS}"), "IP1 should now be flagged")

            # Send one more request from ip2 - should still be fine
            self.assertFalse(is_potential_ddos(ip2, path), "IP2 second request still OK")
            self.assertEqual(ip_tracker[ip2]['count'], 2) # ip2 count increases
            self.assertEqual(ip_tracker[ip1]['count'], MAX_REQUESTS + 1) # ip1 count increases

# Run the tests
if __name__ == '__main__':
    unittest.main()
