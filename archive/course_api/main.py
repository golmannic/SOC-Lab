from fastapi import FastAPI
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from fastapi import Depends, HTTPException

app = FastAPI()

@app.get("/")
def root():
    return {"message": "Welcome Students"}

DATABASE_URL = "sqlite:///books.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class User(Base):
    __tablename__ = "Users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)


class Course(Base):
    __tablename__ = "Course"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    professor = Column(String)
    description = Column(String)

Base.metadata.create_all(bind=engine)



class UserCreate(BaseModel):
    username: str
    password: str = Field(max_length=72)


class CourseCreate(BaseModel):
    title: str
    professor: str
    description: str



pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/register")
def register(user: UserCreate, db: SessionLocal = Depends(get_db)): # type: ignore
    existing = db.query(User).filter(User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    hashed_pw = hash_password(user.password)
    new_user = User(username=user.username, password=hashed_pw)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User created successfully"}

# GET all courses
@app.get("/courses")
def get_courses(db: Session = Depends(get_db)):
    courses = db.query(Course).all()
    return courses


#CREATE courses
@app.post("/courses")
def create_course(course: CourseCreate, db: Session = Depends(get_db)):

    existing = db.query(Course).filter(Course.title == course.title).first()
    if existing:
        raise HTTPException(status_code=400, detail="Course already exists")
    
    new_course = Course(
        title=course.title,
        professor=course.professor,
        description=course.description
    )

    db.add(new_course)
    db.commit()
    db.refresh(new_course)

    return {"message": "Course created successfully", "course": new_course}



# GET single course with ID
@app.get("/course/{course_id}")
def get_course(course_id: int, db: Session = Depends(get_db)):
    course = db.query(Course).filter(Course.id == course_id).first()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    return course


# UPDATE course with ID
@app.put("/courses/{course_id}")
def update_course(course_id: int, updated: CourseCreate, db: Session = Depends(get_db)):
    
    course = db.query(Course).filter(Course.id == course_id).first()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    
    course.title = updated.title
    course.professor = updated.professor
    course.description = updated.description

    db.commit()
    db.refresh(course)

    return{"message": "Course was Created", "course": course}


# DELETE a course
@app.delete("/course/{course_id}")
def delete_course(course_id: int, db: Session = Depends(get_db)):

    course = db.query(Course).filter(Course.id == course_id).first()
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    
    db.delete(course)
    db.commit()

    return{"message": "Course deleted successfully"}