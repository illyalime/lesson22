from sqlalchemy import Column, Integer, String
from database import Base

class User(Base):
    tablename = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String)
    name = Column(String)