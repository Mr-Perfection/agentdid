import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, Integer, LargeBinary, Text, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

class Base(DeclarativeBase):
    pass

class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    did: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    display_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner_email: Mapped[str | None] = mapped_column(Text, nullable=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    email_verify_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    email_verify_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    credential_jwt: Mapped[str | None] = mapped_column(Text, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __init__(self, **kwargs: object) -> None:
        defaults: dict[str, object] = {
            "id": uuid.uuid4,
            "revoked": False,
            "email_verified": False,
            "verification_level": 0,
        }
        for key, val in defaults.items():
            if key not in kwargs:
                kwargs[key] = val() if callable(val) else val
        super().__init__(**kwargs)
