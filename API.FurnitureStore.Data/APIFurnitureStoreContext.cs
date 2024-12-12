using Microsoft.EntityFrameworkCore;
using API.FurnitureStore.Shared;


namespace API.FurnitureStore.Data
{
    public class APIFurnitureStoreContext : DbContext
    {
        //why do we need to make the constructor to inherient from base class and pass it options
        public APIFurnitureStoreContext(DbContextOptions options) : base(options) { }

        public DbSet<Client> Clients { get; set; }
        public DbSet<Product> Products { get; set; }
        public DbSet<Order> Orders { get; set; }
        public DbSet<ProductCategory> ProductCategory { get; set; }

        //what is that override and for what is it for
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlite();
        }

    }
}
