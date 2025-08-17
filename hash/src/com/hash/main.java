package com.hash;

public class main {

	public static void main(String[] args) {
		Md5 md5 = new Md5();
		String hash = md5.digest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".getBytes());
		System.out.println(hash);
	}

}
