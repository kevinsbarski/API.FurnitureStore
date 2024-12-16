using Microsoft.AspNetCore.Mvc;
using API.FurnitureStore.Data;
using API.FurnitureStore.Shared;
using Microsoft.EntityFrameworkCore;

namespace API.FurnitureStore.API.Controllers
{ 
[Route("api/[controller]")]
[ApiController]
public class ProductsController : Controller
{
    private readonly APIFurnitureStoreContext _context;

    public ProductsController(APIFurnitureStoreContext context)
    {
        _context = context;
    }
    [HttpGet]
    public async Task<IEnumerable<Product>> Get()
    {
        return await _context.Products.ToArrayAsync();
    }
    [HttpGet("{id}")]
    public async Task<IActionResult> GetDetails(int id)
    {
        var product = await _context.Products.FirstOrDefaultAsync(p => p.Id == id);
        if (product == null)
        {
            return NotFound();
        }
        return Ok(product);
    }
    [HttpGet("GetByCategory/{productCategoryId}")]
    public async Task<IEnumerable<Product>> GetByCategory(int productCategoryId)
    {
        return await _context.Products
                            .Where(p => p.ProductCategoryId == productCategoryId)
                            .ToListAsync();
                             
    }

    [HttpPost]
    public async Task<IActionResult> Post(Product product)
    {
        await _context.Products.AddAsync(product);
        await _context.SaveChangesAsync();

        return CreatedAtAction("Post", product.Id, product);
    }
    [HttpDelete]
    public async Task<IActionResult> Delete(Product product)
    {
        if(product == null)
        {
            return NotFound();
        }
        _context.Products.Remove(product);
        await _context.SaveChangesAsync();

        return NoContent();
    }

}
}
