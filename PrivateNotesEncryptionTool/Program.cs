#define AUTOMATICTEST
/**
 * PrivateNotes is an encryption scheme and notes encryption tool.
 * Copyright (C) 2010, 2011 Paul Klingelhuber
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 **/
using System;
using System.Collections.Generic;
using System.Text;
using CommandLine.Utility;
using Tomboy.Sync;
using Tomboy.PrivateNotes;
using System.IO;
using Tomboy.PrivateNotes.Crypto;

namespace PrivateNotesEncryptionTool
{
  /// <summary>
  /// Run the program like this:
  /// C:\> pnotes.exe -e test.txt
  /// you get a file test.txt.out
  /// C:\> pnotes.exe -d test.txt.out
  /// the contents are printed and written to the file text.txt.out.out
  /// 
  /// </summary>
  class Program
  {
    public const string FILE_DECRYPT = "d";
    public const string FILE_ENCRYPT = "e";
    public const string OUTPUT_FILE  = "o";
    public const string PASSWORD     = "pw";

#if AUTOMATICTEST
    static void Main(string[] args)
    {
      // encrypt
      Main2(new string[] { "-e", "encryptMe.txt", "-pw", "a" });
      // decrypt
      Main2(new string[] { "-d", "encryptMe.txt.out", "-pw", "a" });
    }

    // when testing automatically, this is NOT the main method (therefore Main2)
    static void Main2(string[] args)
    {
#else
    static void Main(string[] args)
    {
#endif
      Arguments arguments = new Arguments(args);
      String decryptMe = arguments[FILE_DECRYPT];
      String encryptMe = arguments[FILE_ENCRYPT];
      String password = arguments[PASSWORD];
      String outFile = arguments[OUTPUT_FILE];

      if (decryptMe != null || encryptMe != null)
      {
        if (password == null)
          password = readPassword((decryptMe == null) ? true : false);

        if (password == null)
        {
          Console.WriteLine("Exiting.");
          return;
        }

        // construct the path to the output file
        String file = (decryptMe == null) ? encryptMe : decryptMe;
        // THIS VERSION WOULD CREATE AN OUTPUT FOLDER
        //FileInfo inputFileInfo = new FileInfo(file);
        //file = inputFileInfo.DirectoryName;
        //file = Path.Combine(file, "./out/");
        //DirectoryInfo outFolder = new DirectoryInfo(file);
        //if (!outFolder.Exists)
        //  outFolder.Create();
        // END OF FOLDER VERSION

        if (outFile == null)
          //outFile = Path.Combine(outFolder.FullName, inputFileInfo.Name);
          outFile = file + ".out";

        try
        {
          if (decryptMe != null)
          {
            SecurityWrapper.CopyAndDecrypt(decryptMe, outFile, Util.GetBytes(password));
          }
          else if (encryptMe != null)
          {
            SecurityWrapper.CopyAndEncrypt(encryptMe, outFile, Util.GetBytes(password));
          }
        }
        catch (PasswordException)
        {
          Console.WriteLine("ERROR: The password you provided was wrong.");
        }
        catch (IOException _ioe)
        {
          Console.WriteLine("ERROR: Could not access some file: " + _ioe.Message);
        }

      }
      else
      {
        Console.WriteLine("No input file specified, exiting.");
        Console.WriteLine("Usage:\npnotes.exe -d \"todecrypt.bin\" [-o \"outputto.txt\"] [-pw thepassword]");
        Console.WriteLine("pnotes.exe -e \"toencrypt.bin\" [-o \"outputto.txt\"] [-pw thepassword]");
      }
    }

    private static String readPassword(bool _verify)
    {
      Console.Write("Enter the password:");
      String pw1 = readInvisible();
      Console.WriteLine();
      if (_verify)
      {
        Console.Write("Verify password:");
        String pw2 = readInvisible();
        Console.WriteLine();
        if (pw1.Equals(pw2))
          return pw1;

        Console.WriteLine("\nPasswords don't match!");
        return null;
      }
      return pw1;
    }

    private static String readInvisible()
    {
      StringBuilder buffer = new StringBuilder();
      ConsoleKeyInfo keyInfo = Console.ReadKey(true);
      while (keyInfo.Key != ConsoleKey.Enter)
      {
        if (keyInfo.Key == ConsoleKey.Backspace)
        {
          if (buffer.Length > 0)
            buffer.Remove(buffer.Length - 1, 1);
        }
        else
        {
          buffer.Append(keyInfo.KeyChar);
        }
        keyInfo = Console.ReadKey(true);
      }
      return buffer.ToString();
    }
  }
}