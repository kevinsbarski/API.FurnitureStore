using API.FurnitureStore.Data;
using API.FurnitureStore.Shared;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.FurnitureStore.API.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class ProductCategoriesController : Controller
    {
        
            private readonly APIFurnitureStoreContext _context;

            public ProductCategoriesController(APIFurnitureStoreContext context)
            {
                _context = context;
            }

            [HttpGet]
            public async Task<IEnumerable<ProductCategory>> Get()
            {
                return await _context.ProductCategory.ToListAsync();
            }

            [HttpGet("{id}")]
            public async Task<IActionResult> GetDetailes(int id)
            {
                var productCategory = await _context.ProductCategory.FirstOrDefaultAsync(pc => pc.Id == id);
                if (productCategory == null)
                {
                    return NotFound();
                }
                return Ok(productCategory);
            }
            [HttpPost]
            public async Task<IActionResult> Post(ProductCategory productCategory)
            {
                await _context.ProductCategory.AddAsync(productCategory);
                await _context.SaveChangesAsync();

                return CreatedAtAction("Post", productCategory.Id, productCategory);
            }
            [HttpPut]
            public async Task<IActionResult> Put(ProductCategory productCategory)
            {

                _context.ProductCategory.Update(productCategory);
                await _context.SaveChangesAsync();

                return NoContent();
            }
            [HttpDelete]
            public async Task<IActionResult> Delete(ProductCategory productCategory)
            {
                if (productCategory == null)
                {
                    return NotFound();
                }
                _context.ProductCategory.Remove(productCategory);
                await _context.SaveChangesAsync();

                return NoContent();
            }


        }
    }



