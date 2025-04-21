| Test Case | Client IP     | Recency (days) | Frequency | Monetary (bytes) | Expected Outcome                         | Reason                                                                 |
|-----------|---------------|----------------|-----------|------------------|------------------------------------------|------------------------------------------------------------------------|
| 1         | 172.30.0.1    | 0.275          | 11        | 0                | Legitimate User                          | Low frequency, recency not recent                                     |
| 2         | 172.30.0.254  | 0.000510        | 32861     | 0                | DDoS - Flood Attack                      | Extremely recent, extremely high frequency, tiny packets              |
| 3         | 172.30.0.100  | 0.000315       | 5000      | 1500             | DDoS - Amplification Attack              | Extremely recent, high frequency, large packets                       |
| 4         | 172.30.0.200  | 0.000682       | 200       | 300              | Suspicious - Needs Monitoring            | Very recent, moderately high frequency, medium packet size            |
| 5         | 172.30.0.201  | 0.0456           | 95        | 200              | Legitimate User                          | Not recent, frequency under threshold                                 |
| 6         | 172.30.0.202  | 0.0023             | 101       | 800              | Uncertain - Possibly Legit or Slow-Rate Attack | Not very recent, frequency just over threshold, but moderate packet size |
