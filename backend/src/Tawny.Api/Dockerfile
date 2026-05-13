# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY Directory.Build.props Directory.Packages.props ./
COPY src/Tawny.Domain/Tawny.Domain.csproj src/Tawny.Domain/
COPY src/Tawny.Infrastructure/Tawny.Infrastructure.csproj src/Tawny.Infrastructure/
COPY src/Tawny.Jobs/Tawny.Jobs.csproj src/Tawny.Jobs/
COPY src/Tawny.Api/Tawny.Api.csproj src/Tawny.Api/
RUN dotnet restore src/Tawny.Api/Tawny.Api.csproj

COPY src/ src/
RUN dotnet publish src/Tawny.Api/Tawny.Api.csproj -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish ./
EXPOSE 5080
ENV ASPNETCORE_URLS=http://+:5080
ENTRYPOINT ["dotnet", "Tawny.Api.dll"]
