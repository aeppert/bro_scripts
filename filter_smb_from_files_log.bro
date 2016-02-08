event bro_init()
{
  Log::remove_default_filter(Files::LOG);
    Log::add_filter(Files::LOG, [
      $name = "remove-smb-from-files",
      $pred(rec: Files::Info) = {
        if (rec?$source && /SMB/ in rec$source) {
          return F;
        }
      }
  ]);
}
