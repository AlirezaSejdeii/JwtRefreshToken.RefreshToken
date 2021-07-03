using JwtAuthentication.Models.Context;
using JwtAuthentication.Models.ViewModels;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuthentication
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            //must 16 char
            var Secretkey = Encoding.ASCII.GetBytes(Configuration["JwtConfig:Secret"]);
            //must be long
            var EncryptionKey = Encoding.ASCII.GetBytes(Configuration["JwtConfig:EncryptionKey"]);

            //paramer to decode token
            var TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true, // this will validate the 3rd part of the jwt token using the secret that we added in the appsettings and verify we have generated the jwt token
                IssuerSigningKey = new SymmetricSecurityKey(Secretkey), // Add the secret key to our Jwt encryption
                ValidateIssuer = false,
                ValidateAudience = false,
                RequireExpirationTime = true,//make sense token was expir in time
                ValidateLifetime = false,
                ClockSkew = TimeSpan.Zero,
                TokenDecryptionKey = new SymmetricSecurityKey(EncryptionKey)//this for decode token readblity.
            };
            services.AddSingleton(TokenValidationParameters);
            //inject authentication setting
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false;
                options.SaveToken = true;
                options.TokenValidationParameters = TokenValidationParameters;

            });
            //inject JwtConfig object for using this value in controller
            services.Configure<JwtConfig>(Configuration.GetSection("JwtConfig"));


            services.AddControllers()
              .AddNewtonsoftJson(options =>
    options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore);

            //this for implement advance and complite then error handling.

            //.AddXmlDataContractSerializerFormatters()
            //.ConfigureApiBehaviorOptions(setupAction =>
            //{
            //    setupAction.InvalidModelStateResponseFactory = context =>
            //    {
            //        // create a problem details object
            //        var problemDetailsFactory = context.HttpContext.RequestServices
            //                 .GetRequiredService<ProblemDetailsFactory>();
            //        var problemDetails = problemDetailsFactory.CreateValidationProblemDetails(
            //                context.HttpContext,
            //                context.ModelState);

            //        // add additional info not added by default
            //        problemDetails.Detail = "See the errors field for details.";
            //        problemDetails.Instance = context.HttpContext.Request.Path;

            //        // find out which status code to use
            //        var actionExecutingContext =
            //                   context as Microsoft.AspNetCore.Mvc.Filters.ActionExecutingContext;

            //        // if there are modelstate errors & all keys were correctly
            //        // found/parsed we're dealing with validation errors
            //        //
            //        // if the context couldn't be cast to an ActionExecutingContext
            //        // because it's a ControllerContext, we're dealing with an issue 
            //        // that happened after the initial input was correctly parsed.  
            //        // This happens, for example, when manually validating an object inside
            //        // of a controller action.  That means that by then all keys
            //        // WERE correctly found and parsed.  In that case, we're
            //        // thus also dealing with a validation error.
            //        if (context.ModelState.ErrorCount > 0 &&
            //             (context is ControllerContext ||
            //              actionExecutingContext?.ActionArguments.Count == context.ActionDescriptor.Parameters.Count))
            //        {
            //            problemDetails.Status = StatusCodes.Status422UnprocessableEntity;
            //            problemDetails.Title = "Error Occured";

            //            return new UnprocessableEntityObjectResult(problemDetails)
            //            {
            //                ContentTypes = { "application/problem+json" }
            //            };
            //        }

            //        // if one of the arguments wasn't correctly found / couldn't be parsed
            //        // we're dealing with null/unparseable input
            //        problemDetails.Status = StatusCodes.Status400BadRequest;
            //        problemDetails.Title = "Error Occured";

            //        return new BadRequestObjectResult(problemDetails)
            //        {
            //            ContentTypes = { "application/problem+json" }
            //        };
            //    };
            //});

            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Jwt Authentication", Version = "v1" });
                // Set the comments path for the Swagger JSON and UI.
                var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                c.IncludeXmlComments(xmlPath);
            });
            services.AddDbContext<JwtContext>(options => options.UseSqlServer(Configuration.GetConnectionString("JwtAuthDbConnection")));

            //Register identity service
            services.AddDefaultIdentity<IdentityUser>(options =>
            {
                //Change identity defult setting. For password and more
                options.SignIn.RequireConfirmedEmail = true;

                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = true;
                options.Password.RequiredLength = 8;
                options.Password.RequiredUniqueChars = 1;
                //options.Tokens.EmailConfirmationTokenProvider = "theemail";
                // Lockout settings.
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;
            })
             .AddEntityFrameworkStores<JwtContext>()
             .AddDefaultTokenProviders();


            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(10);
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                //c.RoutePrefix = is for runnig from root of site
                app.UseSwaggerUI(c => { c.SwaggerEndpoint("/swagger/v1/swagger.json", "JwtAuthentication v1"); c.RoutePrefix = ""; });
            }

            app.UseSession();

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
