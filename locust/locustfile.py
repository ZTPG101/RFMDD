from locust import HttpUser, task, between

class DDoSSimulation(HttpUser):
    wait_time = between(0.01, 0.05)  # Very rapid requests (tune as needed)

    @task
    def flood(self):
        with self.client.get("/", catch_response=True, timeout=10) as r:
            # if r.status_code != 200:
            r.failure(f"status {r.status_code}") # Simulate a GET flood to the root endpoint