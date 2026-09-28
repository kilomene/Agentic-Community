"""Projects and tasks.

project_create(title, notes) -> id.
task_add(project_id, title, assignee_pid, notes) -> task_id.
task_update(task_id, status, notes).
project_get(project_id, for_peer=None) with 'project_read' gating;
mutating calls for a peer need 'project_write'.
"""
import os
import time

from acp_proto import AcpError


class Projects:
    def __init__(self, store, permissions, audit, owner_pid):
        self._store = store
        self._permissions = permissions
        self._audit = audit
        self._owner = owner_pid

    def create(self, title, notes="", for_peer=None):
        if for_peer is not None:
            self._permissions.check(for_peer, "project_write")
        if not isinstance(title, str) or not title:
            raise AcpError("INTERNAL", "project title must be non-empty")
        proj_id = "proj_" + os.urandom(6).hex()
        now = int(time.time())
        self._store.add_project(proj_id, title, notes or "", self._owner,
                                now)
        self._audit.log("project.created", actor=for_peer or "local",
                        target=proj_id, result="ok",
                        details={"title": title})
        return proj_id

    def add_task(self, project_id, title, assignee_pid=None, notes="",
                 for_peer=None):
        if for_peer is not None:
            self._permissions.check(for_peer, "project_write")
        if self._store.get_project(project_id) is None:
            raise AcpError("NOT_FOUND", f"unknown project {project_id}")
        if not isinstance(title, str) or not title:
            raise AcpError("INTERNAL", "task title must be non-empty")
        task_id = "task_" + os.urandom(6).hex()
        now = int(time.time())
        self._store.add_task(task_id, project_id, title, notes or "",
                             assignee_pid, "pending", 0, self._owner, now,
                             now)
        self._audit.log("task.created", actor=for_peer or "local",
                        target=task_id, result="ok",
                        details={"project": project_id, "title": title,
                                 "assignee": assignee_pid})
        return task_id

    def update_task(self, task_id, status=None, notes=None, for_peer=None):
        if for_peer is not None:
            self._permissions.check(for_peer, "project_write")
        if self._store.get_task(task_id) is None:
            raise AcpError("NOT_FOUND", f"unknown task {task_id}")
        fields = {}
        if status is not None:
            fields["status"] = status
        if notes is not None:
            fields["description"] = notes
        if fields:
            self._store.update_task(task_id, **fields)
        self._audit.log("task.updated", actor=for_peer or "local",
                        target=task_id, result="ok",
                        details={"fields": sorted(fields)})

    def get(self, project_id, for_peer=None):
        if for_peer is not None:
            self._permissions.check(for_peer, "project_read")
        proj = self._store.get_project(project_id)
        if proj is None:
            raise AcpError("NOT_FOUND", f"unknown project {project_id}")
        tasks = self._store.list_tasks(project_id)
        return {
            "id": proj["project_id"],
            "title": proj["name"],
            "notes": proj["description"],
            "created_by": proj["created_by"],
            "created_at": proj["created_at"],
            "tasks": [{
                "id": t["task_id"], "title": t["title"],
                "notes": t["description"], "assignee": t["owner"],
                "status": t["status"], "priority": t["priority"],
                "created_by": t["created_by"],
                "created_at": t["created_at"],
                "updated_at": t["updated_at"],
            } for t in tasks],
        }
