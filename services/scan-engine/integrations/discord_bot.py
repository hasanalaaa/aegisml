import discord
from discord.ext import commands

# Mock setup for Phase 10
intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

@bot.command(name="scan")
async def scan(ctx, url: str):
    embed = discord.Embed(
        title="🛡️ AegisML Scan Report",
        description=f"Scan requested for: {url}",
        color=discord.Color.gold()
    )
    embed.add_field(name="Status", value="Scanning...", inline=False)
    await ctx.send(embed=embed)
