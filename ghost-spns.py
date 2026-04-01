import re
import socket
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes

GUID_REGEX = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)


class NXCModule:
    name = "ghost-spns"
    description = "Finds dangling SPNs for all computer accounts in the domain"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        OUTPUT      Output to file in addition to printing to console
        Examples
        --------
        netexec ldap $DC-IP -u $username -p $password -M enum-spns
        netexec ldap $DC-IP -u $username -p $password -M enum-spns -o OUTPUT=/tmp/spns.txt
        """
        self.output_file = None
        if "OUTPUT" in module_options:
            self.output_file = module_options["OUTPUT"]

    def resolve(self, hostname):
        try:
            socket.gethostbyname(hostname)
            return True
        except socket.gaierror:
            return False

    def is_candidate(self, spn_host, computer_name):
        hostname = spn_host.split(".")[0]
        if GUID_REGEX.match(hostname):
            return False
        if hostname.lower() == computer_name.lower():
            return False
        return True

    def on_login(self, context, connection):
        resp = connection.search(
            searchFilter="(objectCategory=computer)",
            attributes=["dNSHostName", "sAMAccountName", "operatingSystem", "servicePrincipalName"],
        )
        resp_parsed = parse_result_attributes(resp)
        context.log.debug(f"Total number of records returned: {len(resp_parsed)}")

        output_lines = []

        for item in resp_parsed:
            dns_host_name = item.get("dNSHostName")
            sam = item.get("sAMAccountName", "<unknown>")
            os_version = item.get("operatingSystem", "Unknown OS")
            spns = item.get("servicePrincipalName", [])

            if not dns_host_name:
                context.log.debug(f"Skipping computer without dNSHostName: {sam}")
                continue

            if isinstance(spns, str):
                spns = [spns]

            if not spns:
                continue

            computer_name = dns_host_name.split(".")[0].lower()

            if not self.resolve(dns_host_name):
                context.log.debug(f"Computer {dns_host_name} does not resolve, skipping")
                continue

            # resolve each unique candidate host once
            resolve_cache = {}
            for spn in spns:
                match = re.match(r'^[^/]+/([^:/]+)', spn)
                if not match:
                    continue
                spn_host = match.group(1).lower()
                if not self.is_candidate(spn_host, computer_name):
                    continue
                if spn_host not in resolve_cache:
                    resolve_cache[spn_host] = self.resolve(spn_host)

            # only print machines that have at least one dangling SPN
            dangling_spns = []
            for spn in spns:
                match = re.match(r'^[^/]+/([^:/]+)', spn)
                if not match:
                    continue
                spn_host = match.group(1).lower()
                if self.is_candidate(spn_host, computer_name) and not resolve_cache.get(spn_host, True):
                    dangling_spns.append(spn)

            if dangling_spns:
                context.log.highlight(f"{dns_host_name} ({os_version})")
                for spn in dangling_spns:
                    context.log.highlight(f"    [DANGLING] {spn}")
                    output_lines.append(f"{dns_host_name}\t{spn}")

        if not output_lines:
            context.log.info("No dangling SPNs found")

        if self.output_file:
            try:
                with open(self.output_file, "w") as f:
                    f.write("\n".join(output_lines) + "\n")
                context.log.success(f"Results saved to {self.output_file}")
            except Exception as e:
                context.log.fail(f"Failed to write output file: {e}")
