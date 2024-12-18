using Microsoft.EntityFrameworkCore;
using API.FurnitureStore.Shared;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;


namespace API.FurnitureStore.Data
{
    public class APIFurnitureStoreContext : IdentityDbContext
    {
        public APIFurnitureStoreContext(DbContextOptions options) : base(options) { }

        public DbSet<Client> Clients { get; set; }
        public DbSet<Product> Products { get; set; }
        public DbSet<Order> Orders { get; set; }
        public DbSet<ProductCategory> ProductCategory { get; set; }
        public DbSet<OrderDetail> OrderDetails { get; set; }
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlite();
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<OrderDetail>()
                    .HasKey(od => new {od.OrderId,od.ProductId});
        }
    }
}
