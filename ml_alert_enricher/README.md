## Running the Project with Docker

This project uses Docker and Docker Compose to containerize and run a FastAPI application.

### Requirements & Dependencies
- **Python version:** 3.11 (as specified in the Dockerfile: `python:3.11-slim`)
- **Dependencies:** Installed from `requirements.txt` during the Docker build process.

### Environment Variables
- No required environment variables are set by default.
- If you need to use environment variables, you can create a `.env` file in the `./fastapi_app` directory and uncomment the `env_file` line in `docker-compose.yml`.

### Build and Run Instructions
1. **Build and start the services:**
   ```sh
   docker compose up --build
   ```
   This will build the FastAPI app image and start the container.

2. **Access the application:**
   - The FastAPI app will be available at [http://localhost:8000](http://localhost:8000)

### Ports
- **FastAPI app:** Exposes port `8000` (mapped to host `8000`)

### Special Configuration
- The application runs as a non-root user inside the container for improved security.
- No volumes or persistent storage are configured by default.
- No external services (like databases) are required or configured.
- If you add services (e.g., a database), update `depends_on` and `volumes` in `docker-compose.yml` as needed.

---

*Update this section if you add new services, environment variables, or change the exposed ports.*
