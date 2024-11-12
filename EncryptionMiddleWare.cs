// <copyright file="EncryptionMiddleWare.cs" company="Harikrishnan">
// Copyright © Harikrishnan. All rights reserved.
// This computer program may not be used, copied, distributed, corrected, modified,
// translated, transmitted or assigned without Experion's prior written authorization.
// </copyright>
namespace Solution.Project
{
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Http;
    using System.IO;
    using System.Text;
    using System.Text.Json;
    using System.Threading.Tasks;

    /// <summary>
    /// Middleware for encrypting HTTP responses.
    /// </summary>
    public class EncryptionMiddleWare:IMiddleware
    {
	/// <summary>
	/// Defines encryptDecrypt service object
	/// </summary>
	private readonly EncryptDecrypt encryptDecrypt;

	/// <summary>
	/// Initializes a new instance of the <see cref="EncryptionMiddleWare"/> class.
	/// </summary>
	/// <param name="_encryptDecrypt">Service for encryption and decryption operations</param>
	public EncryptionMiddleWare(EncryptDecrypt _encryptDecrypt)
	{
	    encryptDecrypt = _encryptDecrypt;
	}

	/// <summary>
	/// Invokes the middleware, encrypting response data when the HTTP status code is 200 (OK).
	/// </summary>
	/// <param name="context">HTTP context for the current request.</param>
	/// <param name="next">Delegate to invoke the next middleware component.</param>
	public async Task InvokeAsync(HttpContext context, RequestDelegate next)
	{
	    

	    var originalResponseBody = context.Response.Body;

	    
		using (var memoryStream = new MemoryStream())
		{
		    
		    context.Response.Body = memoryStream;

		    await next(context);

		    
		    if (context.Response.StatusCode == StatusCodes.Status200OK)
		    {
			memoryStream.Seek(0, SeekOrigin.Begin);
			var responseBody = await new StreamReader(memoryStream).ReadToEndAsync();

			var modifiedResponse = ModifyResponse(responseBody);

			context.Response.ContentLength = Encoding.UTF8.GetByteCount(modifiedResponse);
			context.Response.Body = originalResponseBody;
			await context.Response.WriteAsync(modifiedResponse);
		    }
		    else
		    {
			
			memoryStream.Seek(0, SeekOrigin.Begin);
			await memoryStream.CopyToAsync(originalResponseBody);
		    }
		}
	    
		context.Response.Body = originalResponseBody;
		

	}

	/// <summary>
	/// Encrypts the response body and formats it as a JSON object.
	/// </summary>
	/// <param name="responseBody">The original response body as a plain text string.</param>
	/// <returns>A JSON-encoded string containing the encrypted data.</returns>
	private string ModifyResponse(string responseBody)
	{   
	    var encryptedResponse = encryptDecrypt.Encrypt(responseBody);

	    var jsonResponse = JsonSerializer.Serialize(new { data = encryptedResponse });

	    return jsonResponse;
	}
    }

    /// <summary>
    /// Extension class for registering the EncryptionMiddleWare in the middleware pipeline.
    /// </summary>
    public static class ClassWithNoInplementationMiddlewareExtension
    {
	/// <summary>
	/// Adds the EncryptionMiddleWare to the application's middleware pipeline.
	/// </summary>
	/// <param name="builder">The application builder.</param>
	/// <returns>The modified application builder.</returns>
	public static IApplicationBuilder UseClassWithNoImplementationMiddleware(this IApplicationBuilder builder)
	{
	    return builder.UseMiddleware<EncryptionMiddleWare>();
	}
    }
}
