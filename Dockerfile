# ---------- Build ----------
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Restore first, in its own layer, so dependencies are cached until a project file changes.
COPY src/Sentinel.Shared/Sentinel.Shared.csproj src/Sentinel.Shared/
COPY src/Sentinel.Web/Sentinel.Web.csproj src/Sentinel.Web/
COPY src/Sentinel.Api/Sentinel.Api.csproj src/Sentinel.Api/
RUN dotnet restore src/Sentinel.Api/Sentinel.Api.csproj

COPY src/ src/
RUN dotnet publish src/Sentinel.Api/Sentinel.Api.csproj -c Release -o /app --no-restore

# ---------- Runtime ----------
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .

# Run as the image's built-in unprivileged user, never as root.
USER $APP_UID
ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_RUNNING_IN_CONTAINER=true
EXPOSE 8080

ENTRYPOINT ["dotnet", "Sentinel.Api.dll"]
