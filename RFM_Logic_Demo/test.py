import unittest

# RFM Detection Logic Function
def classify_client(recency_days, frequency, monetary):
    LOW_RECENCY = 1 / 1440
    HIGH_FREQUENCY = 100
    LOW_MONETARY = 100
    HIGH_MONETARY = 1200


    if recency_days < LOW_RECENCY and frequency > HIGH_FREQUENCY:
        if monetary < LOW_MONETARY:
            return "DDoS - Flood Attack"
        elif monetary > HIGH_MONETARY:
            return "DDoS - Amplification Attack"
        else:
            return "Suspicious - Needs Monitoring"
    elif frequency <= HIGH_FREQUENCY:
        return "Legitimate User"
    else:
        return "Uncertain - Possibly Legit or Slow-Rate Attack"


class TestRFMDetection(unittest.TestCase):
    def test_case_1(self):
        self.assertEqual(
            classify_client(0.275, 11, 0),
            "Legitimate User"
        )

    def test_case_2(self):
        self.assertEqual(
            classify_client(0.000510, 32861, 0),
            "DDoS - Flood Attack"
        )

    def test_case_3(self):
        self.assertEqual(
            classify_client(0.000315, 5000, 1500),
            "DDoS - Amplification Attack"
        )

    def test_case_4(self):
        self.assertEqual(
            classify_client(0.000682, 200, 300),
            "Suspicious - Needs Monitoring"
        )

    def test_case_5(self):
        self.assertEqual(
            classify_client(0.0456, 95, 200),
            "Legitimate User"
        )

    def test_case_6(self):
        self.assertEqual(
            classify_client(0.0023, 101, 800),
            "Uncertain - Possibly Legit or Slow-Rate Attack"
        )


if __name__ == '__main__':
    unittest.main()
