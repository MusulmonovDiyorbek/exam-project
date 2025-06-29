import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Req } from '@nestjs/common';
import { ResultsService } from './results.service';
import { CreateResultDto } from './dto/create-result.dto';
import { UpdateResultDto } from './dto/update-result.dto';
import { JwtAuthGuard } from 'src/auth/guard/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guard/roles.guard';
import { Request } from 'express';
import { Roles } from 'src/auth/decorators/role.decorator';

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('results')
export class ResultsController {
  constructor(private readonly resultsService: ResultsService) { }
  @Post()
  @Roles('teacher','admin')
  create(@Req() req: Request, @Body() createResultDto: CreateResultDto) {
    const teacher = req.user as any;
    return this.resultsService.create(teacher, createResultDto);
  }

  @Get()
  @Roles('student')
  findStudent(@Req() req: Request) {
    const student = req.user as any
    return this.resultsService.findAllByStudent(student.id)
  }

  @Patch(':id')
  @Roles('teacher','admin')
  update(@Param('id') id: string, @Body() updateResultDto: UpdateResultDto) {
    return this.resultsService.update(+id, updateResultDto);
  }
  
  @Delete(':id')
  @Roles('teacher','admin')
  remove(@Param('id') id: string) {
    return this.resultsService.remove(+id);
  }
}
