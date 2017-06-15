import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;

public class LZWEncoder {
	int bitcnt = 9;
	int dicode = 256 + 2;
	int[] dictbl = new int[256 * 4096];

	static int[] test_mask = {
		1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80,
		0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000,
		0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000, 0x800000,
		0x1000000, 0x2000000, 0x4000000, 0x8000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000
	};

	static int[] dictbltest = new int[32 * 1024];

	void restart()
	{
		bitcnt = 9;
		dicode = (256 + 2);
		java.util.Arrays.fill(dictbltest, 0);
	}

	int find(int prefix, int code)
	{
		int key = (prefix << 8) | code;
		if ((dictbltest[key >> 5] &
					test_mask[key & 0x1F]) > 0)
			return dictbl[key];
		return -1;
	}


	int update(int prefix, int code)
	{
		int key = (prefix << 8) | code;
		dictbltest[key >> 5] |= test_mask[key & 0x1F];
		dictbl[key] = dicode++;
		return dicode;
	}


	int outbitcnt = 0;
	int outbitbuff = 0;

	int outcnt = 0;
	byte[] outbuff = new byte[8192 + 4];

	void output(int code, OutputStream file) throws Exception
	{
		int i;
		int mask = (1 << bitcnt) - 1;

		outbitbuff |= ((code & mask) << outbitcnt);
		outbitcnt += bitcnt;

		while (outbitcnt >= 8) {
			byte outch = (byte)(outbitbuff & 0xFF);
			outbuff[outcnt++] = outch;
			outbitbuff >>= 8;
			outbitcnt -= 8;
		}

		if (outcnt >= 8192) {
			for (i = 0; i + 255 <= outcnt; i += 255) {
				file.write(0xFF);
				file.write(outbuff, i, 255);
			}
			outcnt -= i;
			System.arraycopy(outbuff, i, outbuff, 0, outcnt);
		}

		if (mask < dicode){
			++bitcnt;
		}
	}

	void finish(int code, OutputStream file) throws Exception
	{
		int i;
		output(code, file);
		output(257, file);

		if (outbitcnt > 0) {
			byte outch = (byte)(outbitbuff & 0xFF);
			outbuff[outcnt++] = outch;
		}

		int cpcnt = 0;
		for (i = 0; i < outcnt; i += cpcnt) {
			cpcnt = 0xFF;
			if (cpcnt + i > outcnt)
				cpcnt = outcnt - i;
			file.write(cpcnt);
			file.write(outbuff, i, cpcnt);
		}

		file.write(0);
		outcnt = 0;
	}

	public int convert(String pathin, String pathout) throws Exception
	{
		int i, j;
		byte[] buffer = new byte[8192];
		OutputStream outStream = new BufferedOutputStream(new FileOutputStream(pathout));

		int prefix = -1;

		FileInputStream inStream = new FileInputStream(pathin);

		prefix = -1;
		restart();
		output(256, outStream);

		byte[] line_data = new byte[8192];
		for (int count = inStream.read(line_data); count > 0; count = inStream.read(line_data)) {
			for (j = 0; j < count; j++) {
				int code = line_data[j] & 0xFF;
				if (prefix == -1){
					prefix = code;
					continue;
				}
				int prefix1 = find(prefix, code);
				if (prefix1 != -1){
					prefix = prefix1;
					continue;
				}
				output(prefix, outStream);
				if (update(prefix, code) < 4096){
					prefix = code;
					continue;
				}
				output(256, outStream);
				prefix = code;
				restart();
			}
		}

		finish(prefix, outStream);
		outStream.close();
		inStream.close();
		return 0;
	}

	public static void main(String[] args) {
		try {
			LZWEncode encoder = new LZWEncode();
			if (args.length > 1)
				encoder.convert(args[0], args[1]);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}

