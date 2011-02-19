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
using System.IO;
using Tomboy.PrivateNotes.Crypto;
using Tomboy.PrivateNotes;

namespace Tomboy.Sync
{
  /// <summary>
  /// security wrapper for the local encrypted FileSystemSynchronization
  /// </summary>
  class SecurityWrapper
  {

    public static void CopyAndEncrypt(String _inputFile, String _toFile, byte[] _password)
    {

      FileStream input = File.OpenRead(_inputFile);
      MemoryStream membuf = new MemoryStream();
      int b = input.ReadByte();
      while (b >= 0)
      {
        membuf.WriteByte((byte)b);
        b = input.ReadByte();
      }
      input.Close();

      byte[] salt;
      byte[] key = AESUtil.CalculateSaltedHash(_password, out salt);

      CryptoFormat ccf = CryptoFormatProviderFactory.INSTANCE.GetCryptoFormat();
      ccf.WriteCompatibleFile(_toFile, membuf.ToArray(), key, salt);
    }

    public static void CopyAndDecrypt(String _inputFile, String _toFile, byte[] _password)
    {
      bool ok = false;
      CryptoFormat ccf = CryptoFormatProviderFactory.INSTANCE.GetCryptoFormat();
      byte[] data = ccf.DecryptFile(_inputFile, _password, out ok);

      if (!ok)
      {
        Console.WriteLine("Not written");
        return;
      }

      // write out
      FileStream output = File.OpenWrite(_toFile);
      for (int i = 0; i < data.Length; i++)
      {
        output.WriteByte(data[i]);
      }
      output.Close(); 
    }

    public static void SaveAsEncryptedFile(String _fileName, byte[] _data, byte[] _password)
    {
      CryptoFormat ccf = CryptoFormatProviderFactory.INSTANCE.GetCryptoFormat();

      byte[] salt;
      byte[] key = AESUtil.CalculateSaltedHash(_password, out salt);
      ccf.WriteCompatibleFile(_fileName, _data, key, salt);
    }

    public static Stream DecryptFromStream(String _inputFile, Stream _s, byte[] _key, out bool  _wasOk)
    {
      CryptoFormat ccf = CryptoFormatProviderFactory.INSTANCE.GetCryptoFormat();
      byte[] data = ccf.DecryptFromStream(_inputFile, _s, _key, out _wasOk);
      if (!_wasOk)
        return null;

      return new MemoryStream(data);
    }



  }
}
