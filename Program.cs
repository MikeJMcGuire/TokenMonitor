using System;
using System.Net.Http;
using System.Threading;

namespace TokenMonitor
{
	class Program
	{
		static void Main(string[] args)
		{
			HttpClient httpClient = new HttpClient();
			ManualResetEvent eventStop = new ManualResetEvent(false);

			Authentication.Initialise("user", "password", eventStop, httpClient);
		}
	}
}
