"""Database setup and models for agent-user mappings."""

import os
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Database path - use SQLite for lightweight deployment
DATABASE_PATH = os.getenv("DATABASE_PATH", "mappings.db")
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

# Create engine with SQLite
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite
    echo=False
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declarative base for models
Base = declarative_base()


class AgentUserMapping(Base):
    """
    Maps Wazuh agent IDs to Okta user emails and cloud PC identifiers.
    
    Attributes:
        id: Primary key
        okta_user_email: Okta user email (e.g., user@example.com)
        wazuh_agent_id: Wazuh agent ID (e.g., "001"), unique and indexed
        cloud_pc_id: Cloud PC identifier (e.g., "DEV-PC-001")
        is_vip: Flag to mark VIP users for higher priority handling
    """
    __tablename__ = "agent_user_mapping"
    
    id = Column(Integer, primary_key=True, index=True)
    okta_user_email = Column(String(255), nullable=False)
    wazuh_agent_id = Column(String(100), nullable=False, unique=True, index=True)
    cloud_pc_id = Column(String(255), nullable=True)
    is_vip = Column(Boolean, default=False)
    
    # Create index for faster lookups
    __table_args__ = (
        Index("ix_agent_id", "wazuh_agent_id"),
    )
    
    def __repr__(self):
        return (
            f"<AgentUserMapping(id={self.id}, email={self.okta_user_email}, "
            f"agent_id={self.wazuh_agent_id}, pc={self.cloud_pc_id}, vip={self.is_vip})>"
        )


def init_db():
    """Initialize database tables."""
    Base.metadata.create_all(bind=engine)
    print(f"✓ Database initialized at {DATABASE_PATH}")


def get_db():
    """Dependency for FastAPI to get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# CRUD operations
def create_mapping(db, okta_user_email: str, wazuh_agent_id: str, 
                   cloud_pc_id: str = None, is_vip: bool = False) -> AgentUserMapping:
    """
    Create a new agent-user mapping.
    
    Args:
        db: Database session
        okta_user_email: Okta user email
        wazuh_agent_id: Wazuh agent ID
        cloud_pc_id: Optional cloud PC identifier
        is_vip: Optional VIP flag
    
    Returns:
        AgentUserMapping instance
    """
    mapping = AgentUserMapping(
        okta_user_email=okta_user_email,
        wazuh_agent_id=wazuh_agent_id,
        cloud_pc_id=cloud_pc_id,
        is_vip=is_vip
    )
    db.add(mapping)
    db.commit()
    db.refresh(mapping)
    return mapping


def get_mapping_by_agent_id(db, wazuh_agent_id: str):
    """
    Retrieve mapping by Wazuh agent ID.
    
    Args:
        db: Database session
        wazuh_agent_id: Wazuh agent ID to look up
    
    Returns:
        AgentUserMapping instance or None if not found
    """
    return db.query(AgentUserMapping).filter(
        AgentUserMapping.wazuh_agent_id == wazuh_agent_id
    ).first()


def get_all_mappings(db):
    """
    Retrieve all mappings.
    
    Args:
        db: Database session
    
    Returns:
        List of AgentUserMapping instances
    """
    return db.query(AgentUserMapping).all()


def update_mapping(db, wazuh_agent_id: str, **kwargs) -> AgentUserMapping:
    """
    Update an existing mapping.
    
    Args:
        db: Database session
        wazuh_agent_id: Wazuh agent ID
        **kwargs: Fields to update (okta_user_email, cloud_pc_id, is_vip)
    
    Returns:
        Updated AgentUserMapping instance
    """
    mapping = get_mapping_by_agent_id(db, wazuh_agent_id)
    if mapping:
        for key, value in kwargs.items():
            if hasattr(mapping, key):
                setattr(mapping, key, value)
        db.commit()
        db.refresh(mapping)
    return mapping


def delete_mapping(db, wazuh_agent_id: str) -> bool:
    """
    Delete a mapping.
    
    Args:
        db: Database session
        wazuh_agent_id: Wazuh agent ID
    
    Returns:
        True if deleted, False if not found
    """
    mapping = get_mapping_by_agent_id(db, wazuh_agent_id)
    if mapping:
        db.delete(mapping)
        db.commit()
        return True
    return False
