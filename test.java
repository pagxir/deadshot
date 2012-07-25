import java.net.InetSocketAddress;

public class test {

	public static void main(String[] args) {
		InetSocketAddress ias;
		ias = new InetSocketAddress("192.168.0.1", 8201);
		System.out.println(ias);
		System.out.println(ias.getAddress().getAddress().length);
	}
}

