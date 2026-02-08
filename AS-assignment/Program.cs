using AceJobAgency.Models;
using AceJobAgency.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddSingleton<EncryptionService>();
builder.Services.AddScoped<PasswordSecurityService>();
builder.Services.AddScoped<TwoFactorService>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddHttpClient();

// FIX 2: Connect to Database correctly using your Connection String
// We do NOT use AddIdentity here because we are building security from scratch.
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("AuthConnectionString")));

// FIX 3: Add Session support (Required for the assignment's Login/Logout features)
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20); // Set timeout as required
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

builder.Services.AddScoped<RecaptchaService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    // Handle 404 (Not Found) and other HTTP status codes
    app.UseStatusCodePagesWithReExecute("/Errors/General", "?code={0}");

    app.UseExceptionHandler("/Errors/General");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// FIX 4: Enable Session before Authorization
app.UseSession();

app.UseAuthorization();
// Note: We don't use app.UseAuthentication() here because we are handling it manually in the Login Code.

app.MapRazorPages();

app.Run();