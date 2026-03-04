from nxc.helpers.misc import CATEGORY
from nxc.logger import nxc_logger
from impacket.ldap.ldap import LDAPSearchError
from impacket.ldap.ldapasn1 import SearchResultEntry
from datetime import datetime, timedelta, timezone
import sys


class NXCModule:
    """
    Lists enabled computer accounts whose pwdLastSet is older than supplied DAYS
    """

    name = "stale-computers"
    description = "Lists enabled computer accounts with pwdLastSet older than supplied DAYS"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):

        if "DAYS" not in module_options:
            context.log.error("DAYS option is required!")
            sys.exit(1)

        try:
            self.DAYS = int(module_options["DAYS"])
        except ValueError:
            context.log.error("DAYS must be an integer")
            sys.exit(1)

    def filetime_to_dt(self, filetime):
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(filetime) / 10)

    def on_login(self, context, connection):

        search_filter = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

        try:
            context.log.debug(f"Search Filter={search_filter}")
            resp = connection.ldap_connection.search(
                searchFilter=search_filter,
                attributes=["dNSHostName", "pwdLastSet"],
                sizeLimit=0
            )
        except LDAPSearchError as e:
            if "sizeLimitExceeded" in e.getErrorString():
                resp = e.getAnswers()
            else:
                nxc_logger.debug(e)
                return False

        cutoff = datetime.now(timezone.utc) - timedelta(days=self.DAYS)

        found = False

        for item in resp:
            if not isinstance(item, SearchResultEntry):
                continue

            hostname = None
            pwd_last_set_raw = None

            try:
                for attribute in item["attributes"]:
                    if str(attribute["type"]) == "dNSHostName":
                        hostname = str(attribute["vals"][0])
                    elif str(attribute["type"]) == "pwdLastSet":
                        pwd_last_set_raw = str(attribute["vals"][0])

                if not hostname or not pwd_last_set_raw or pwd_last_set_raw == "0":
                    continue

                pwd_dt = self.filetime_to_dt(pwd_last_set_raw)

                if pwd_dt < cutoff:
                    if not found:
                        context.log.success(
                            f"Enabled computers with pwdLastSet older than {self.DAYS} days:"
                        )
                        found = True

                    context.log.highlight(f"{hostname} - pwdLastSet: {pwd_dt}")

            except Exception:
                context.log.debug("Error processing entry", exc_info=True)

        if not found:
            context.log.success("No matching computer accounts found.")
