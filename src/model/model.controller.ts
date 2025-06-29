import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards } from '@nestjs/common';
import { ModelService } from './model.service';
import { CreateModelDto } from './dto/create-model.dto';
import { UpdateModelDto } from './dto/update-model.dto';
import { JwtAuthGuard } from 'src/auth/guard/jwt-auth.guard';
import { Roles } from 'src/auth/decorators/role.decorator';
import { RolesGuard } from 'src/auth/guard/roles.guard';

@UseGuards(JwtAuthGuard,RolesGuard)
@Controller('model')
export class ModelController {
  constructor(private readonly modelService: ModelService) {}
  
  @Post()
  @Roles('admin', 'teacher') 
  create(@Body() createModelDto: CreateModelDto) {
    return this.modelService.create(createModelDto);
  }

  @Get()
  @Roles('admin', 'teacher', 'student')
  findAll() {
    return this.modelService.findAll();
  }

  @Get(':id')
  @Roles('admin', 'teacher', 'student')
  findByCourseID(@Param('id') id: string) {
    return this.modelService.findByCourseId(+id);
  }

  @Patch(':id')
  @Roles('admin', 'teacher')
  update(@Param('id') id: string, @Body() updateModelDto: UpdateModelDto) {
    return this.modelService.update(+id, updateModelDto);
  }

  @Delete(':id')
  @Roles('admin', 'teacher')
  remove(@Param('id') id: string) {
    return this.modelService.remove(+id);
  }
}
