using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TokenMonitor
{
	public class Authentication
	{
		private static string _strBaseURL = "https://target.web.service";
		private static string _strDeviceIdFile = "/data/deviceid.json";
		private static string _strPairingTokenFile = "/data/pairingtoken.json";
		private static string _strBearerTokenFile = "/data/bearertoken.json";
		private static string _strUser, _strPassword, _strDeviceUniqueIdentifier;
		private static HttpClient _httpClient = null, _httpClientAuth = null;
		private static int _iCancellationTime = 15; // Seconds
		private static int _iAuthenticationInterval = 60; // Seconds
		private static ManualResetEvent _eventStop;
		private static AutoResetEvent _eventAuthenticationFailure = new AutoResetEvent(false);
		private static PairingToken _pairingToken;
		private static BearerToken _bearerToken = null;

		public AutoResetEvent AuthenticationFailure
		{
			get { return _eventAuthenticationFailure; }
		}

		static Authentication()
		{
			HttpClientHandler httpClientHandler = new HttpClientHandler();

			if (httpClientHandler.SupportsAutomaticDecompression)
				httpClientHandler.AutomaticDecompression = System.Net.DecompressionMethods.All;

			_httpClientAuth = new HttpClient(httpClientHandler);

			_httpClientAuth.BaseAddress = new Uri(_strBaseURL);
		}

		public static void Initialise(string strUser, string strPassword, ManualResetEvent eventStop, HttpClient httpClient)
		{
			Thread threadMonitor;

			_strUser = strUser;
			_strPassword = strPassword;
			_eventStop = eventStop;
			_httpClient = httpClient;

			// Get Device Id
			try
			{
				if (File.Exists(_strDeviceIdFile))
					_strDeviceUniqueIdentifier = JsonConvert.DeserializeObject<string>(File.ReadAllText(_strDeviceIdFile));
			}
			catch (Exception eException)
			{
				// Handle Error
			}

			// Get Pairing Token
			try
			{
				if (File.Exists(_strPairingTokenFile))
					_pairingToken = JsonConvert.DeserializeObject<PairingToken>(File.ReadAllText(_strPairingTokenFile));
			}
			catch (Exception eException)
			{
				// Handle Error
			}

			threadMonitor = new Thread(new ThreadStart(TokenMonitor));
			threadMonitor.Start();
		}

		private static async Task<bool> GeneratePairingToken()
		{
			HttpResponseMessage httpResponse = null;
			CancellationTokenSource cancellationToken = null;
			Dictionary<string, string> dtFormContent = new Dictionary<string, string>();
			string strPageURL = "/api/authenticate";
			string strResponse;
			dynamic jsonResponse;
			bool bRetVal = true;

			if (_strDeviceUniqueIdentifier == "")
			{
				_strDeviceUniqueIdentifier = GenerateDeviceId();

				// Update Device Id File
				try
				{
					File.WriteAllText(_strDeviceIdFile, JsonConvert.SerializeObject(_strDeviceUniqueIdentifier));
				}
				catch (Exception eException)
				{
					// Handle Error
				}
			}

			// Add Authentication Parameters
			dtFormContent.Add("username", _strUser);
			dtFormContent.Add("password", _strPassword);
			dtFormContent.Add("deviceUniqueIdentifier", _strDeviceUniqueIdentifier);

			try
			{
				cancellationToken = new CancellationTokenSource();
				cancellationToken.CancelAfter(TimeSpan.FromSeconds(_iCancellationTime));

				httpResponse = await _httpClientAuth.PostAsync(strPageURL, new FormUrlEncodedContent(dtFormContent), cancellationToken.Token);

				if (httpResponse.IsSuccessStatusCode)
				{
					strResponse = await httpResponse.Content.ReadAsStringAsync();

					jsonResponse = JsonConvert.DeserializeObject(strResponse);

					_pairingToken = new PairingToken(jsonResponse.pairingToken.ToString());

					// Update Token File
					try
					{
						File.WriteAllText(_strPairingTokenFile, JsonConvert.SerializeObject(_pairingToken));
					}
					catch (Exception eException)
					{
						// Handle Error
					}
				}
				else
				{
					// Handle Error
					bRetVal = false;
					goto Cleanup;
				}
			}
			catch (OperationCanceledException eException)
			{
				// Handle Error

				bRetVal = false;
				goto Cleanup;
			}
			catch (Exception eException)
			{
				// Handle Error

				bRetVal = false;
				goto Cleanup;
			}

		Cleanup:
			cancellationToken?.Dispose();
			httpResponse?.Dispose();

			if (!bRetVal)
				_pairingToken = null;

			return bRetVal;
		}

		private static async Task<bool> GenerateBearerToken()
		{
			HttpResponseMessage httpResponse = null;
			CancellationTokenSource cancellationToken = null;
			Dictionary<string, string> dtFormContent = new Dictionary<string, string>();
			BearerToken bearerToken = null;
			string strPageURL = "/api/gettoken";
			string strResponse;
			dynamic jsonResponse;
			bool bRetVal = true;

			// Add Authenticaiton Parameters
			dtFormContent.Add("refresh_token", _pairingToken.Token);
			

			try
			{
				cancellationToken = new CancellationTokenSource();
				cancellationToken.CancelAfter(TimeSpan.FromSeconds(_iCancellationTime));

				httpResponse = await _httpClientAuth.PostAsync(strPageURL, new FormUrlEncodedContent(dtFormContent), cancellationToken.Token);

				if (httpResponse.IsSuccessStatusCode)
				{
					strResponse = await httpResponse.Content.ReadAsStringAsync();

					jsonResponse = JsonConvert.DeserializeObject(strResponse);

					bearerToken = new BearerToken();
					bearerToken.Token = jsonResponse.access_token;
					bearerToken.TokenExpires = DateTime.Now.AddSeconds(int.Parse(jsonResponse.expires_in.ToString()));

					_bearerToken = bearerToken;

					_httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _bearerToken.Token);
					
					// Update Token File
					try
					{
						File.WriteAllText(_strBearerTokenFile, JsonConvert.SerializeObject(_bearerToken));
					}
					catch (Exception eException)
					{
						// Handle Error
					}
				}
				else
				{
					if (httpResponse.StatusCode == System.Net.HttpStatusCode.Unauthorized)
					{
						// Pairing Token Invalid
						_pairingToken = null;
					}
					else
					{
						// Handle Error
					}

					bRetVal = false;
					goto Cleanup;
				}
			}
			catch (OperationCanceledException eException)
			{
				// Handle Error

				bRetVal = false;
				goto Cleanup;
			}
			catch (Exception eException)
			{
				// Handle Error

				bRetVal = false;
				goto Cleanup;
			}

		Cleanup:
			cancellationToken?.Dispose();
			httpResponse?.Dispose();

			if (!bRetVal)
				_bearerToken = null;

			return bRetVal;
		}

		private async static void TokenMonitor()
		{
			WaitHandle[] waitHandles = new WaitHandle[] { _eventStop, _eventAuthenticationFailure };
			int iWaitHandle = 0;
			bool bExit = false;

			if (_pairingToken == null)
			{
				if (await GeneratePairingToken())
					await GenerateBearerToken();
			}
			else
				await GenerateBearerToken();

			while (!bExit)
			{
				iWaitHandle = WaitHandle.WaitAny(waitHandles, TimeSpan.FromSeconds(_iAuthenticationInterval));

				switch (iWaitHandle)
				{
					case 0: // Stop
						bExit = true;

						break;

					case 1: // Authentication Failure
						if (_pairingToken == null)
						{
							if (await GeneratePairingToken())
								await GenerateBearerToken();
						}
						else
							await GenerateBearerToken();

						break;

					case WaitHandle.WaitTimeout: // Wait Timeout
						if (_pairingToken == null)
						{
							if (await GeneratePairingToken())
								await GenerateBearerToken();
						}
						else if (_bearerToken == null)
							await GenerateBearerToken();
						else if (_bearerToken != null && _bearerToken.TokenExpires <= DateTime.Now.Subtract(TimeSpan.FromMinutes(5)))
						{
							// Refresh Bearer Token
							await GenerateBearerToken();
						}

						break;
				}
			}
		}		

		public static bool IsTokenValid()
		{
			if (_bearerToken != null && _bearerToken.TokenExpires > DateTime.Now)
				return true;
			else
				return false;
		}

		private static string GenerateDeviceId()
		{
			Random random = new Random();
			int iLength = 25;

			StringBuilder sbDeviceId = new StringBuilder();

			for (int iIndex = 0; iIndex < iLength; iIndex++)
				sbDeviceId.Append(random.Next(0, 9));

			return sbDeviceId.ToString();
		}
	}
}
