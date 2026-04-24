from pydantic_settings import BaseSettings, SettingsConfigDict, PydanticBaseSettingsSource

class TestSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")
    test_var: str = "default"

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        return (dotenv_settings,)

print("Imported successfully")
