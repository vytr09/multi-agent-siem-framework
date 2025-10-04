"""
Database connection and management for the Multi-Agent SIEM Framework.
"""

import asyncio
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, AsyncEngine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import NullPool
from agents.base.exceptions import DatabaseException
from core.logging import get_agent_logger

# SQLAlchemy declarative base
Base = declarative_base()

class DatabaseManager:
    """
    Manages database connections and sessions for the multi-agent system.
    
    Provides async database operations with connection pooling and
    proper session management.
    """
    
    def __init__(self, database_url: str):
        """
        Initialize database manager.
        
        Args:
            database_url: Database connection URL
        """
        self.database_url = database_url
        self.engine: Optional[AsyncEngine] = None
        self.async_session_maker: Optional[sessionmaker] = None
        self.logger = get_agent_logger("database")
    
    async def initialize(self) -> None:
        """Initialize database engine and session maker"""
        try:
            # Create async engine
            self.engine = create_async_engine(
                self.database_url,
                echo=False,  # Set to True for SQL query logging
                pool_pre_ping=True,  # Verify connections before use
                pool_recycle=3600,   # Recycle connections after 1 hour
                max_overflow=20,     # Max connections beyond pool_size
                pool_size=10,        # Base number of connections
            )
            
            # Create session maker
            self.async_session_maker = sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            self.logger.info("Database manager initialized successfully")
            
        except Exception as e:
            raise DatabaseException(f"Failed to initialize database: {str(e)}")
    
    async def close(self) -> None:
        """Close database engine and all connections"""
        if self.engine:
            await self.engine.dispose()
            self.logger.info("Database connections closed")
    
    def get_session(self) -> AsyncSession:
        """
        Get a new database session.
        
        Returns:
            AsyncSession instance
        """
        if not self.async_session_maker:
            raise DatabaseException("Database not initialized. Call initialize() first.")
        
        return self.async_session_maker()
    
    async def create_tables(self) -> None:
        """Create all database tables"""
        try:
            if not self.engine:
                raise DatabaseException("Database engine not initialized")
            
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            self.logger.info("Database tables created successfully")
            
        except Exception as e:
            raise DatabaseException(f"Failed to create tables: {str(e)}")
    
    async def drop_tables(self) -> None:
        """Drop all database tables (use with caution!)"""
        try:
            if not self.engine:
                raise DatabaseException("Database engine not initialized")
            
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)
            
            self.logger.info("Database tables dropped")
            
        except Exception as e:
            raise DatabaseException(f"Failed to drop tables: {str(e)}")
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform database health check.
        
        Returns:
            Dict with health status information
        """
        try:
            if not self.engine:
                return {"status": "error", "message": "Engine not initialized"}
            
            # Test connection
            async with self.engine.begin() as conn:
                result = await conn.execute("SELECT 1")
                row = result.fetchone()
            
            if row and row[0] == 1:
                return {
                    "status": "healthy", 
                    "message": "Database connection successful",
                    "url": self.database_url.split("@")[-1]  # Hide credentials
                }
            else:
                return {"status": "error", "message": "Database query failed"}
                
        except Exception as e:
            return {
                "status": "error", 
                "message": f"Database health check failed: {str(e)}"
            }

# Global database manager instance
_database_manager: Optional[DatabaseManager] = None

def get_database_manager(database_url: str = None) -> DatabaseManager:
    """
    Get the global database manager instance.
    
    Args:
        database_url: Database connection URL
        
    Returns:
        DatabaseManager instance
    """
    global _database_manager
    
    if _database_manager is None:
        if not database_url:
            from core.config import get_config
            database_url = get_config().settings.database_url
        
        _database_manager = DatabaseManager(database_url)
    
    return _database_manager

async def init_database() -> None:
    """Initialize the global database manager"""
    db_manager = get_database_manager()
    await db_manager.initialize()
    await db_manager.create_tables()
