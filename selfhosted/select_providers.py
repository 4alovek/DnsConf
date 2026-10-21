"""Keep SELFHOSTED out of the Java provider/credential lists."""
import os


def select(value):
    providers = [item.strip().upper() for item in value.split(",") if item.strip()]
    unknown = set(providers) - {"SELFHOSTED", "NEXTDNS", "CLOUDFLARE"}
    if unknown:
        raise ValueError(f"Unknown DNS providers: {', '.join(sorted(unknown))}")
    cloud = [item for item in providers if item != "SELFHOSTED"]
    return cloud, "SELFHOSTED" in providers


if __name__ == "__main__":
    cloud, selfhosted = select(os.environ.get("DNS", ""))
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"cloud={str(bool(cloud)).lower()}\n")
        output.write(f"selfhosted={str(selfhosted).lower()}\n")
    with open(os.environ["GITHUB_ENV"], "a") as environment:
        environment.write(f"DNS={','.join(cloud)}\n")
