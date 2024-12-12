﻿using API.FurnitureStore.Data;
using API.FurnitureStore.Shared;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.FurnitureStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ClientsController : Controller
    {
        private readonly APIFurnitureStoreContext _context;

        public ClientsController(APIFurnitureStoreContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<IEnumerable<Client>> Get()
        {
            return await _context.Clients.ToListAsync();
        }
        [HttpGet("{id}")]
        public async Task<IActionResult> GetDetailes(int id)
        {
            var client = await _context.Clients.FirstOrDefaultAsync(c => c.id == id);
            if(client == null)
            {
                return NotFound();
            }
            return Ok(client);
        }


    }
}