## In Program.cs

```
builder.Services.AddSingleton(new EncryptDecrypt(Environment.GetEnvironmentVariable("SECRET_KEY")));

builder.Services.AddTransient<EncryptionMiddleWare>();  //Middleware

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseClassWithNoImplementationMiddleware();
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseCors("AllowLocalhost");
}
```
