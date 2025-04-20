| Test Case | Client IP       | Recency (days) | Frequency | Monetary (bytes) | Expected Outcome                          | Reason                                                                 |
|-----------|------------------|----------------|-----------|------------------|-------------------------------------------|------------------------------------------------------------------------|
| 1         | 172.30.0.1       | 0.275          | 11        | 0                | Legitimate User                           | Low frequency, recency not very recent                                |
| 2         | 172.30.0.254     | 0.0625         | 32861     | 0                | DDoS - Flood Attack                       | Very recent, high frequency, tiny packets                             |
| 3         | 172.30.0.100     | 0.0005         | 5000      | 1500             | DDoS - Amplification Attack               | Very recent, high frequency, large packets                            |
| 4         | 172.30.0.200     | 0.0009         | 200       | 300              | Suspicious - Needs Monitoring             | Very recent, moderately high frequency, average-size packets          |
| 5         | 172.30.0.201     | 0.02           | 95        | 200              | Legitimate User                           | Frequency below threshold                                             |
| 6         | 172.30.0.202     | 0.0012         | 101       | 800              | Uncertain - Possibly Legit or Slow-Rate Attack | Just over frequency threshold, but not extremely suspicious      |
