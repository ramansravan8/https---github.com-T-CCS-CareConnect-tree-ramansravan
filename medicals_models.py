from sqlalchemy import Boolean,Column, Integer, String,ForeignKey,Text,DateTime,TIMESTAMP
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from medicals_database import Base


class MedicalReport(Base):
    __tablename__ = 'Medicals_val'  # replace with your actual table name if different

    report_id = Column(Integer, primary_key=True, nullable=False,)
    patient_id = Column(Integer, nullable=True)
    center_id = Column(Integer, nullable=True)
    test_details = Column(Text, nullable=False)
    upload_date = Column(TIMESTAMP, server_default=func.current_timestamp(), nullable=False)


    # Constraints are handled by SQLAlchemy automatically
    __table_args__ = (
        {'schema': 'public'},  # Optional: Specify schema if needed
    )



from sqlalchemy import Column, Integer, String
from medicals_database import Base

class User(Base):
    __tablename__ = "Sign_up"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)