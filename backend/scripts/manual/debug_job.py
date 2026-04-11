import requests
import time
import sys

API_URL = "http://127.0.0.1:8000/api"

def debug_job(job_id):
    print(f"Monitoring Job {job_id}...")
    while True:
        try:
            res = requests.get(f"{API_URL}/jobs/{job_id}")
            if res.status_code == 200:
                job = res.json()
                print(f"Status: {job['status']}")
                if job['logs']:
                    print(f"Last Log: {job['logs'][-1]}")
                
                if job['status'] in ['success', 'failed', 'error']:
                    break
            else:
                print("Job not found")
                break
        except:
            print("Connection error")
            break
        time.sleep(1)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        debug_job(sys.argv[1])
    else:
        print("Usage: python debug_job.py <job_id>")