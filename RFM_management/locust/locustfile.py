from locust import HttpUser, task, between

class DDoSSimulation(HttpUser):
    wait_time = between(0.01, 0.05)  # Very rapid requests (tune as needed)

    @task
    def flood(self):
        self.client.get("/")  # Simulate a GET flood to the root endpoint