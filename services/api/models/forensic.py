from pydantic import BaseModel
from typing import Optional
import uuid

class ForensicCheckpointRequest(BaseModel):
    """
    Recieved based on the Falco alerts directly(not pulled from postgres db right now), for now due to the container plugin issue, 
    let's take the container_name, pod_name and namespace as input, unless we fix it in future
    """

    rule: str
    priority: str
    output: str
    output_fields: Optional[dict] = None
    tags: Optional[list[str]] = None
    container_name: str
    pod_name: str
    namespace: str = "default"

class ForensicCheckpointResponse(BaseModel):
    status: str             #"accepted", "rejected/error/ignored", "duplicate" 
    forensic_checkpoint_id: str
    message: Optional[str] = None


