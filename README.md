# FastAPI Course Registration API

A small FastAPI + SQLAlchemy CRUD service for managing users and courses. Built as a backend-fundamentals exercise, not a security project — see note below.

## What it does

- `POST /register` — create a user (password hashed with bcrypt via `passlib`)
- `GET /courses` / `POST /courses` — list / create courses
- `GET /course/{id}` / `PUT /courses/{id}` / `DELETE /course/{id}` — read, update, delete a single course

Data is persisted to a local SQLite database (`books.db`) via SQLAlchemy models (`User`, `Course`).

## Run it

```bash
pip install fastapi sqlalchemy passlib[bcrypt] uvicorn
uvicorn main:app --reload
```

Then explore the endpoints at `http://127.0.0.1:8000/docs`.

## Note on the name

This repo was originally named `SOC-Lab` and described as a SOC (security operations) simulation, which this code does not actually do — it's a course/user CRUD API with no log analysis, detection logic, or SIEM/ATT&CK content. Renaming it to reflect what it actually is (rather than leaving a misleading name) so the repo matches its content.
