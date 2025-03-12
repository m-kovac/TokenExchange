using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Rsk.TokenExchange.Validators.Adaptors;

namespace Rsk.TokenExchange.Validators
{
    /// <summary>
    /// Wrapper around IdentityServer's ITokenValidator
    /// Returns success for any token issued by IdentityServer.
    /// </summary>
    public class DefaultSubjectTokenValidator : ISubjectTokenValidator
    {
        private readonly ITokenValidatorAdaptor tokenValidator;
        private readonly ILogger<ISubjectTokenValidator> logger;

        /// <summary>
        /// Creates a new IdentityServerSubjectTokenValidator
        /// </summary>
        public DefaultSubjectTokenValidator(ITokenValidatorAdaptor tokenValidator, ILogger<ISubjectTokenValidator> logger)
        {
            this.tokenValidator = tokenValidator ?? throw new ArgumentNullException(nameof(tokenValidator));
            this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <inheritdoc />
        public async Task<ISubjectTokenValidationResult> Validate(string token, string tokenType)
        {
            if (string.IsNullOrWhiteSpace(token)) throw new ArgumentNullException(nameof(token));
            if (string.IsNullOrWhiteSpace(tokenType)) throw new ArgumentNullException(nameof(tokenType));
            TokenValidationResult validationResult;
            // Write more elegant
            switch (tokenType)
            {
                case TokenExchangeConstants.TokenTypes.AccessToken:
                    validationResult = await tokenValidator.ValidateAccessToken(token);
                    if (validationResult.IsError)
                    {
                        logger.LogError("Received invalid token");
                        return SubjectTokenValidationResult.Failure();
                    }
                    break;
                case TokenExchangeConstants.TokenTypes.RefreshToken:
                    validationResult = await tokenValidator.ValidateRefreshToken(token);
                    if (validationResult.IsError)
                    {
                        logger.LogError("Received invalid token");
                        return SubjectTokenValidationResult.Failure();
                    }
                    break;
                default:
                    logger.LogError($"Received unsupported token type of {tokenType}");
                    return SubjectTokenValidationResult.Failure();
            }



            return SubjectTokenValidationResult.Success(validationResult.Claims);
        }
    }
}